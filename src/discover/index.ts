import { inflateSync } from 'node:zlib';
import { address, createAddressWithSeed, getAddressDecoder, getProgramDerivedAddress, isOffCurveAddress } from '@solana/kit';
import { PROGRAMS, SQUADS_PROGRAMS } from '../constants.js';
import type { ParsedEventsClient } from '../helius/parsedEvents.js';
import type { FungibleHolding, RpcClient } from '../helius/rpc.js';
import { account, fromParsedEvents, normalizeName } from '../model.js';
import { checkBuild, type BuildCheck } from './build.js';
import { isAdminRole, namesType, PRIMITIVE_SIZE, summarizeIdl, type ConfigLayout, type IdlSummary } from './idl.js';
import { mintControls, type MintControl } from './token2022.js';
import { decodeMultisig, findVaultIndex, type SquadsMultisig } from './squads.js';

type AuthorityKind = 'immutable' | 'wallet' | 'squads' | 'unknown-pda';

export interface ProgramState {
    programId: string;
    programData: string;
    upgradeAuthority: string | null;
    authorityKind: AuthorityKind;
    lastDeploySlot: number;
    multisig: (SquadsMultisig & { vaultIndex: number }) | null;
    idl: IdlSummary | null;
    admins: AdminAuthority[];
    vaults: Vault[];
    configAccounts: ConfigAccount[];
    /** Config account types with an admin field whose accounts could not be found. */
    unlocatedConfigs: string[];
    /** `null` when the verification service could not be reached. */
    build: BuildCheck | null;
}

interface AdminAuthority {
    key: string;
    /** IDL signer role, or `Account.field` for a key read from a config account. */
    role: string;
    kind: Exclude<AuthorityKind, 'immutable'>;
    multisig: (SquadsMultisig & { vaultIndex: number }) | null;
}

export interface ConfigAccount {
    address: string;
    layout: ConfigLayout;
    values: Record<string, string>;
}

export interface Vault {
    /** Owner of the vault's token accounts. */
    authority: string;
    usd: number;
    holdings: FungibleHolding[];
}

export interface MintState {
    address: string;
    tokenProgram: string;
    mintAuthority: string | null;
    freezeAuthority: string | null;
    supply: bigint;
    decimals: number;
    /** Empty for SPL Token mints. */
    controls: MintControl[];
}

const UPGRADEABLE_PROGRAM_TAG = 2;
const UPGRADEABLE_PROGRAM_DATA_TAG = 3;
const MINT_SIZE = 82;
const MULTISIG_DISCOVERY_SCAN_BUDGET = 10_000;

/** `idlAtSlot` selects the IDL version live at that slot instead of the latest. */
export async function discoverProgram(
    rpc: RpcClient,
    events: ParsedEventsClient,
    programId: string,
    idlAtSlot?: number,
): Promise<ProgramState> {
    const program = await rpc.getAccountInfo(programId);
    if (!program) throw new Error(`Program ${programId} not found`);
    if (program.owner !== PROGRAMS.bpfLoaderUpgradeable || readU32(program.data, 0) !== UPGRADEABLE_PROGRAM_TAG) {
        throw new Error(`${programId} is not an upgradeable-loader program (owner ${program.owner})`);
    }
    const programData = readAddress(program.data, 4);

    const dataAccount = await rpc.getAccountInfo(programData);
    if (!dataAccount || readU32(dataAccount.data, 0) !== UPGRADEABLE_PROGRAM_DATA_TAG) {
        throw new Error(`ProgramData account ${programData} is missing or malformed`);
    }
    const lastDeploySlot = Number(view(dataAccount.data).getBigUint64(4, true));
    const upgradeAuthority = dataAccount.data[12] === 1 ? readAddress(dataAccount.data, 13) : null;

    const [multisig, idl, build] = await Promise.all([
        upgradeAuthority ? findGoverningMultisig(rpc, events, upgradeAuthority) : null,
        fetchIdl(events, programId, idlAtSlot, rpc),
        checkBuild(rpc, programId, programData).catch((error: Error) => {
            console.warn(`Failed to check the verified build of ${programId}: ${error.message}`);
            return null;
        }),
    ]);

    let authorityKind: AuthorityKind = 'immutable';
    if (upgradeAuthority) {
        if (multisig) authorityKind = 'squads';
        else if (isOffCurveAddress(address(upgradeAuthority))) authorityKind = 'unknown-pda';
        else authorityKind = 'wallet';
    }

    return {
        programId,
        programData,
        upgradeAuthority,
        authorityKind,
        lastDeploySlot,
        multisig,
        idl,
        admins: [],
        vaults: [],
        configAccounts: [],
        unlocatedConfigs: [],
        build,
    };
}

const ADMIN_SCAN_BUDGET = 10_000;
const ADMIN_SCAN_MATCHES = 20;
const MAX_ADMIN_KEYS = 5;
const MAX_CONFIG_ACCOUNTS = 20;

const CONFIG_SAMPLE_TRANSACTIONS = 50;
const CONFIG_SAMPLE_BUDGET = 2_000;
const CONFIG_REFERRERS = 5;
/** A sampled account counts as a protocol setting only when it carries this share of its type's recent use. */
const CONFIG_MIN_SHARE = 0.25;
const CONFIG_MAX_SAMPLED = 3;

/**
 * Instances of the IDL's config account types, in three ways:
 * - Types with constant-seed PDAs are read at those addresses. Types derived per entity (a mint, a user) are skipped.
 * - Others are listed from the program when they have at most `MAX_CONFIG_ACCOUNTS` accounts.
 * - Types with more, or that cannot be listed (a program with millions of accounts), are found in a sample of recent
 *   transactions: accounts passed under the type's name, or named by another account's field, such as a pool's
 *   `whirlpools_config`. Only the most used are kept, which also drops per-user data.
 *
 * The program's own types come first, so its admin fields name the roles. `unlocated` lists types that could not be
 * listed and were not seen in the sample.
 */
export async function discoverConfigAccounts(
    rpc: RpcClient,
    events: ParsedEventsClient,
    programId: string,
    idl: IdlSummary | null,
): Promise<{ accounts: ConfigAccount[]; unlocated: string[] }> {
    const ownedElsewhere = (layout: ConfigLayout) =>
        layout.pdas.length > 0 && layout.pdas.every((p) => p.program !== null && p.program !== programId);
    const layouts = (idl?.configLayouts ?? []).toSorted((a, b) => Number(ownedElsewhere(a)) - Number(ownedElsewhere(b)));
    const accounts: ConfigAccount[] = [];
    const crowded: ConfigLayout[] = [];
    const unlisted: ConfigLayout[] = [];
    for (const layout of layouts) {
        if (layout.pdas.length > 0) {
            accounts.push(...(await readConfigPdas(rpc, programId, layout)));
            continue;
        }
        if (layout.perEntity) continue;
        const { slices, more } = await rpc.getAccountSlices(programId, layout.discriminator, 0, layout.length, MAX_CONFIG_ACCOUNTS + 1);
        if (slices.length > MAX_CONFIG_ACCOUNTS) crowded.push(layout);
        else if (more && slices.length === 0) unlisted.push(layout);
        else for (const { pubkey, data } of slices) accounts.push({ address: pubkey, layout, values: decodeConfig(data, layout) });
    }
    const unlocated: string[] = [];
    if (crowded.length + unlisted.length > 0) {
        const recent = await recentAccountsByName(events, programId);
        for (const layout of [...crowded, ...unlisted]) {
            const found = await mostUsedInSample(rpc, layout, recent);
            if (found.length === 0 && unlisted.includes(layout)) unlocated.push(layout.account);
            accounts.push(...found);
        }
    }
    return { accounts, unlocated };
}

/** How often the program's recent instructions passed each account, by IDL account name. */
async function recentAccountsByName(events: ParsedEventsClient, programId: string): Promise<Map<string, Map<string, number>>> {
    const counts = new Map<string, Map<string, number>>();
    const scan = events.scanAll(
        {
            address: programId,
            match: { programs: [{ programId, scope: 'transaction' }] },
            status: 'succeeded',
            sortOrder: 'desc',
            limit: CONFIG_SAMPLE_TRANSACTIONS,
        },
        CONFIG_SAMPLE_BUDGET,
    );
    let sampled = 0;
    for await (const result of scan) {
        for (const ix of fromParsedEvents(result)?.instructions ?? []) {
            if (ix.programId !== programId) continue;
            for (const { name, pubkey } of ix.accounts ?? []) {
                const byKey = counts.get(name) ?? new Map<string, number>();
                counts.set(name, byKey.set(pubkey, (byKey.get(pubkey) ?? 0) + 1));
            }
        }
        if (++sampled >= CONFIG_SAMPLE_TRANSACTIONS) break;
    }
    return counts;
}

/** Accounts of `layout`'s type carrying at least `CONFIG_MIN_SHARE` of its use in the sample, directly or through referrers. */
async function mostUsedInSample(rpc: RpcClient, layout: ConfigLayout, recent: Map<string, Map<string, number>>): Promise<ConfigAccount[]> {
    const passedAs = (accountType: string) => {
        const merged = new Map<string, number>();
        for (const [name, byKey] of recent) {
            if (namesType(name, accountType)) for (const [key, count] of byKey) merged.set(key, (merged.get(key) ?? 0) + count);
        }
        return merged;
    };
    const uses = passedAs(layout.account);
    for (const ref of layout.referencedBy) {
        const referrers = [...passedAs(ref.account)].sort((a, b) => b[1] - a[1]).slice(0, CONFIG_REFERRERS);
        if (referrers.length === 0) continue;
        const { data } = await rpc.getMultipleAccountsData(referrers.map(([key]) => key));
        referrers.forEach(([, count], i) => {
            const account = data[i];
            if (!account || account.length < ref.offset + 32 || !hasDiscriminator(account, ref.discriminator)) return;
            const target = readAddress(account, ref.offset);
            uses.set(target, (uses.get(target) ?? 0) + count);
        });
    }
    const ranked = [...uses].sort((a, b) => b[1] - a[1]).slice(0, MAX_CONFIG_ACCOUNTS);
    if (ranked.length === 0) return [];
    const { data } = await rpc.getMultipleAccountsData(ranked.map(([key]) => key));
    const verified = ranked.flatMap(([pubkey, count], i) => {
        const account = data[i];
        if (!account || account.length < layout.length || !hasDiscriminator(account, layout.discriminator)) return [];
        return [{ count, account: { address: pubkey, layout, values: decodeConfig(account.subarray(0, layout.length), layout) } }];
    });
    const total = verified.reduce((sum, v) => sum + v.count, 0);
    return verified
        .filter((v) => v.count >= Math.max(2, total * CONFIG_MIN_SHARE))
        .slice(0, CONFIG_MAX_SAMPLED)
        .map((v) => v.account);
}

function hasDiscriminator(data: Uint8Array, hex: string): boolean {
    return Buffer.from(data.subarray(0, 8)).toString('hex') === hex;
}

async function readConfigPdas(rpc: RpcClient, programId: string, layout: ConfigLayout): Promise<ConfigAccount[]> {
    const addresses = await Promise.all(
        layout.pdas.map(
            async ({ seeds, program }) =>
                (
                    await getProgramDerivedAddress({
                        programAddress: address(program ?? programId),
                        seeds: seeds.map((seed) => Buffer.from(seed, 'hex')),
                    })
                )[0],
        ),
    );
    const { data } = await rpc.getMultipleAccountsData(addresses);
    return addresses.flatMap((pubkey, i) => {
        const account = data[i];
        if (!account || account.length < layout.length || !hasDiscriminator(account, layout.discriminator)) return [];
        return [{ address: pubkey, layout, values: decodeConfig(account.subarray(0, layout.length), layout) }];
    });
}

/** Field values as strings: base58 keys, decimal integers, `true`/`false`. */
export function decodeConfig(data: Uint8Array, layout: ConfigLayout): Record<string, string> {
    const dataView = view(data);
    const values: Record<string, string> = {};
    for (const { name, offset, type } of layout.fields) {
        if (offset + (PRIMITIVE_SIZE.get(type) ?? Infinity) > data.length) continue;
        values[name] = readField(dataView, data, offset, type);
    }
    return values;
}

function readField(view: DataView, data: Uint8Array, offset: number, type: string): string {
    switch (type) {
        case 'pubkey':
            return readAddress(data, offset);
        case 'bool':
            return String(data[offset] === 1);
        case 'u8':
            return String(view.getUint8(offset));
        case 'i8':
            return String(view.getInt8(offset));
        case 'u16':
            return String(view.getUint16(offset, true));
        case 'i16':
            return String(view.getInt16(offset, true));
        case 'u32':
            return String(view.getUint32(offset, true));
        case 'i32':
            return String(view.getInt32(offset, true));
        case 'f32':
            return String(view.getFloat32(offset, true));
        case 'u64':
            return view.getBigUint64(offset, true).toString();
        case 'i64':
            return view.getBigInt64(offset, true).toString();
        case 'f64':
            return String(view.getFloat64(offset, true));
        case 'u128':
            return (view.getBigUint64(offset, true) + (view.getBigUint64(offset + 8, true) << 64n)).toString();
        default:
            return (view.getBigUint64(offset, true) + (view.getBigInt64(offset + 8, true) << 64n)).toString();
    }
}

/**
 * Admin keys from config-account admin fields, admin-role signers of recent privileged calls, and `known` (key → role).
 * Keys from config accounts are kept only when they are a wallet or a Squads vault.
 */
export async function discoverAdmins(
    rpc: RpcClient,
    events: ParsedEventsClient,
    programId: string,
    configAccounts: ConfigAccount[],
    privilegedInstructions: string[],
    known: Map<string, string>,
): Promise<AdminAuthority[]> {
    // Insertion order is priority: the current admins in config accounts, then recent signers, then keys from earlier runs.
    const roles = new Map<string, string>();
    const fromAccounts = new Set<string>();
    const singleAccountRoles: [key: string, role: string][] = [];
    for (const config of configAccounts) {
        const single = config.layout.pdas.length > 0 && !config.layout.perEntity;
        for (const field of config.layout.fields.filter((f) => f.admin)) {
            const key = config.values[field.name];
            if (key && single) singleAccountRoles.push([key, roleName(field.name)]);
            if (!key || key === PROGRAMS.system || roles.has(key)) continue;
            roles.set(key, `${config.layout.account}.${field.name}`);
            fromAccounts.add(key);
        }
    }
    if (privilegedInstructions.length > 0) {
        const scan = events.scanAll(
            {
                address: programId,
                match: { programs: [{ programId, instructions: privilegedInstructions.slice(0, 50), scope: 'transaction' }] },
                status: 'succeeded',
                sortOrder: 'desc',
                limit: ADMIN_SCAN_MATCHES,
            },
            ADMIN_SCAN_BUDGET,
        );
        let matched = 0;
        for await (const result of scan) {
            for (const ix of fromParsedEvents(result)?.instructions ?? []) {
                if (ix.programId !== programId) continue;
                for (const signer of ix.accounts?.filter((a) => a.isSigner && isAdminRole(a.name)) ?? []) {
                    if (!roles.has(signer.pubkey)) roles.set(signer.pubkey, signer.name);
                }
            }
            if (++matched >= ADMIN_SCAN_MATCHES) break;
        }
    }
    for (const [key, role] of known) if (!roles.has(key)) roles.set(key, role);
    const admins = await Promise.all(
        [...roles].slice(0, MAX_ADMIN_KEYS * 2).map(async ([key, role]): Promise<AdminAuthority> => {
            if (!isOffCurveAddress(address(key))) return { key, role, kind: 'wallet', multisig: null };
            const multisig = await findGoverningMultisig(rpc, events, key);
            return { key, role, kind: multisig ? 'squads' : 'unknown-pda', multisig };
        }),
    );
    const kept = admins.filter((a) => !(fromAccounts.has(a.key) && a.kind === 'unknown-pda'));
    const keptKeys = new Set(kept.map((a) => a.key));
    const heldRoles = new Set(singleAccountRoles.filter(([key]) => key === PROGRAMS.system || keptKeys.has(key)).map(([, role]) => role));
    return kept.filter((a) => fromAccounts.has(a.key) || !heldRoles.has(roleName(a.role))).slice(0, MAX_ADMIN_KEYS);
}

/** The field or signer name of a role, without the `Account.` prefix of a key read from a config account. */
function roleName(role: string): string {
    return normalizeName(role.slice(role.lastIndexOf('.') + 1));
}

const VAULT_SCAN_BUDGET = 3_000;
const VAULT_SCAN_MATCHES = 300;
const VAULT_CANDIDATES = 3;
const VAULT_MIN_HOLDING_USD = 10_000;
const VAULT_MIN_TOTAL_USD = 100_000;

/** Off-curve addresses paying out tokens in the program's recent transactions, kept when their DAS-priced holdings are large enough. */
export async function discoverVaults(rpc: RpcClient, events: ParsedEventsClient, programId: string): Promise<Vault[]> {
    const payers = new Map<string, number>();
    const scan = events.scanAll(
        {
            address: programId,
            match: { programs: [{ programId, scope: 'transaction' }] },
            status: 'succeeded',
            sortOrder: 'desc',
            limit: 100,
        },
        VAULT_SCAN_BUDGET,
    );
    let matched = 0;
    for await (const result of scan) {
        for (const transfer of result.parsed?.tokenTransfers ?? []) {
            const from = transfer.fromUserAccount;
            if (from && from !== programId && isOffCurveAddress(address(from))) payers.set(from, (payers.get(from) ?? 0) + 1);
        }
        if (++matched >= VAULT_SCAN_MATCHES) break;
    }
    const candidates = [...payers].sort((a, b) => b[1] - a[1]).slice(0, VAULT_CANDIDATES);
    const vaults: Vault[] = [];
    for (const [authority] of candidates) {
        const holdings = (await rpc.getFungibleHoldings(authority)).filter((h) => (h.usd ?? 0) >= VAULT_MIN_HOLDING_USD);
        const usd = holdings.reduce((sum, h) => sum + (h.usd ?? 0), 0);
        if (usd >= VAULT_MIN_TOTAL_USD) vaults.push({ authority, usd, holdings: holdings.sort((a, b) => (b.usd ?? 0) - (a.usd ?? 0)) });
    }
    return vaults;
}

export async function discoverMint(rpc: RpcClient, mint: string): Promise<MintState> {
    const info = await rpc.getAccountInfo(mint);
    if (!info || !isMintAccount(info.owner, info.data)) {
        throw new Error(`${mint} is not an SPL Token or Token-2022 mint`);
    }
    return {
        address: mint,
        tokenProgram: info.owner,
        mintAuthority: readU32(info.data, 0) === 1 ? readAddress(info.data, 4) : null,
        supply: view(info.data).getBigUint64(36, true),
        decimals: info.data[44] ?? 0,
        freezeAuthority: readU32(info.data, 46) === 1 ? readAddress(info.data, 50) : null,
        controls: info.owner === PROGRAMS.token2022 ? mintControls(info.data) : [],
    };
}

/** System-owned nonce accounts: 80 bytes, version u32, state u32, then the authority. */
const NONCE_ACCOUNT_SIZE = 80;
const NONCE_AUTHORITY_OFFSET = 8;
/** System instruction tags (bincode u32): advance, initialize and authorize nonce account. */
const NONCE_DISCRIMINATORS = ['0x04000000', '0x06000000', '0x07000000'];
const NONCE_SCAN_BUDGET = 10_000;
const NONCE_SCAN_CONCURRENCY = 4;

/** Durable nonce accounts each key controls: candidates from the key's own nonce instructions, confirmed on-chain. */
export async function findNonceAccounts(rpc: RpcClient, events: ParsedEventsClient, keys: string[]): Promise<Map<string, string[]>> {
    const found = new Map<string, string[]>();
    const queue = [...keys];
    const worker = async () => {
        for (let key = queue.shift(); key; key = queue.shift()) found.set(key, await nonceAccountsOf(rpc, events, key));
    };
    await Promise.all(Array.from({ length: NONCE_SCAN_CONCURRENCY }, worker));
    return found;
}

async function nonceAccountsOf(rpc: RpcClient, events: ParsedEventsClient, key: string): Promise<string[]> {
    const candidates = new Set<string>();
    const scan = events.scanAll(
        {
            address: key,
            match: { programs: [{ programId: PROGRAMS.system, discriminators: NONCE_DISCRIMINATORS, scope: 'address' }] },
            status: 'succeeded',
            limit: 100,
        },
        NONCE_SCAN_BUDGET,
    );
    for await (const result of scan) {
        for (const ix of fromParsedEvents(result)?.instructions ?? []) {
            const nonce = ix.programId === PROGRAMS.system ? account(ix, 'nonce_account')?.pubkey : undefined;
            if (nonce) candidates.add(nonce);
        }
    }
    const controlled: string[] = [];
    for (const nonce of candidates) {
        const info = await rpc.getAccountInfo(nonce);
        if (
            info?.owner === PROGRAMS.system &&
            info.data.length === NONCE_ACCOUNT_SIZE &&
            readAddress(info.data, NONCE_AUTHORITY_OFFSET) === key
        ) {
            controlled.push(nonce);
        }
    }
    return controlled;
}

export async function loadMultisig(rpc: RpcClient, multisigAddress: string): Promise<SquadsMultisig> {
    const multisig = await readMultisig(rpc, multisigAddress);
    if (!multisig) throw new Error(`${multisigAddress} is not a Squads v3 or v4 multisig`);
    return multisig;
}

async function readMultisig(rpc: RpcClient, multisigAddress: string): Promise<SquadsMultisig | null> {
    const info = await rpc.getAccountInfo(multisigAddress);
    return info ? decodeMultisig(multisigAddress, info.owner, info.data) : null;
}

/** A base mint is 82 bytes; a Token-2022 mint with extensions marks account type 1 at byte 165. */
function isMintAccount(owner: string, data: Uint8Array): boolean {
    if (owner === PROGRAMS.splToken) return data.length === MINT_SIZE;
    if (owner === PROGRAMS.token2022) return data.length === MINT_SIZE || (data.length > 165 && data[165] === 1);
    return false;
}

/** Candidates are multisigs in Squads instructions from the authority's history, confirmed by re-deriving the vault. */
async function findGoverningMultisig(
    rpc: RpcClient,
    events: ParsedEventsClient,
    authority: string,
): Promise<(SquadsMultisig & { vaultIndex: number }) | null> {
    if (!isOffCurveAddress(address(authority))) return null;

    const checked = new Set<string>();
    const scan = events.scanAll(
        {
            address: authority,
            match: { programs: SQUADS_PROGRAMS.map((programId) => ({ programId, scope: 'transaction' as const })) },
            status: 'succeeded',
            limit: 25,
        },
        MULTISIG_DISCOVERY_SCAN_BUDGET,
    );
    for await (const result of scan) {
        for (const ix of fromParsedEvents(result)?.instructions ?? []) {
            if (!SQUADS_PROGRAMS.includes(ix.programId)) continue;
            const candidate = account(ix, 'multisig')?.pubkey ?? ix.rawAccounts?.[0];
            if (!candidate || checked.has(candidate)) continue;
            checked.add(candidate);
            const multisig = await readMultisig(rpc, candidate);
            const vaultIndex = multisig ? await findVaultIndex(multisig.version, candidate, authority) : null;
            if (multisig && vaultIndex !== null) return { ...multisig, vaultIndex };
        }
    }
    return null;
}

/**
 * The program's IDL from Parsed Events. Some stored IDLs carry instructions only; for those, account layouts come from
 * the program's on-chain Anchor IDL when `rpc` is given.
 */
export async function fetchIdl(
    events: ParsedEventsClient,
    programId: string,
    atSlot?: number,
    rpc?: RpcClient,
): Promise<IdlSummary | null> {
    try {
        const versions = await events.listIdlVersions(programId);
        const version = atSlot === undefined ? versions.at(-1) : versions.filter((v) => v.slot <= atSlot).at(-1);
        if (!version) return null;
        const idl = (await events.getIdl(programId, version.slot)) as { accounts?: unknown[] } | null;
        if (!rpc || (idl?.accounts?.length ?? 0) > 0) return summarizeIdl(idl);
        const onChain = await onChainAnchorIdl(rpc, programId).catch((error: Error) => {
            console.warn(`Failed to read the on-chain IDL of ${programId}: ${error.message}`);
            return null;
        });
        return summarizeIdl(onChain ? { ...idl, accounts: onChain.accounts, types: onChain.types } : idl);
    } catch (error) {
        console.warn(`Failed to load the IDL for ${programId}: ${(error as Error).message}`);
        return null;
    }
}

/**
 * Anchor's IDL account, at `createWithSeed(PDA(program, []), "anchor:idl", program)` and owned by the program:
 * an 8-byte discriminator, the 32-byte authority, a u32 length, then that many bytes of zlib-compressed JSON.
 */
async function onChainAnchorIdl(rpc: RpcClient, programId: string): Promise<{ accounts?: unknown[]; types?: unknown[] } | null> {
    const [base] = await getProgramDerivedAddress({ programAddress: address(programId), seeds: [] });
    const idlAddress = await createAddressWithSeed({ baseAddress: base, programAddress: address(programId), seed: 'anchor:idl' });
    const account = await rpc.getAccountInfo(idlAddress);
    if (!account || account.owner !== programId || account.data.length < 44) return null;
    const length = readU32(account.data, 40);
    return JSON.parse(inflateSync(account.data.subarray(44, 44 + length)).toString('utf8'));
}

function readAddress(data: Uint8Array, offset: number): string {
    return getAddressDecoder().decode(data.subarray(offset, offset + 32));
}

function readU32(data: Uint8Array, offset: number): number {
    return view(data).getUint32(offset, true);
}

function view(data: Uint8Array): DataView {
    return new DataView(data.buffer, data.byteOffset, data.byteLength);
}
