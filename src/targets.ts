import type { Config } from './config.js';
import { FALLBACK_SLOT_MS, PROGRAMS, SQUADS_PROGRAMS } from './constants.js';
import { MINT_EXTENSION_UPDATES } from './detectors/mintAuthority.js';
import { DELEGATE_MOVES } from './detectors/permanentDelegate.js';
import type { WatchedMultisig, WatchedTreasury, WatchTargets } from './detectors/types.js';
import type { MintState, OwnedTokenAccount, ProgramState, Vault } from './discover/index.js';
import type { SquadsMultisig } from './discover/squads.js';
import { formatAmount, short } from './format.js';
import type { ScanMatch } from 'helius-sdk/parsedEvents/types';
import type { ScanRequest } from './helius/parsedEvents.js';
import type { Subscription } from './helius/parsedStreams.js';
import { normalizeName } from './model.js';
import type { StateStore } from './state.js';

export interface Discovery {
    programs: ProgramState[];
    mints: MintState[];
    /** Multisigs listed in config, beyond those discovered as upgrade authorities. */
    multisigs: SquadsMultisig[];
    /** Token accounts of treasuries and discovered vaults. */
    tokenAccounts: OwnedTokenAccount[];
}

export interface ScanPlan {
    key: string;
    label: string;
    address: string;
    match: ScanMatch;
    status: NonNullable<ScanRequest['status']>;
    /** Also scan transactions that touch only a token account `address` owns, such as one a delegate signs. */
    tokenAccounts?: NonNullable<ScanRequest['tokenAccounts']>;
    /** Detectors whose findings about `subject` this plan is responsible for. */
    detectors: string[];
    subject: string;
    /** Start the cursor at the present instead of scanning the lookback window, whose findings would be silent anyway. */
    skipFirstScan?: true;
}

/** Parsed Streams per-filter and per-connection limits; Parsed Events per-match scan limits. */
const STREAM_MAX_INSTRUCTION_NAMES = 50;
const STREAM_MAX_INCLUDED_ACCOUNTS = 100;
const STREAM_MAX_SUBSCRIPTIONS = 25;
const SCAN_MAX_INSTRUCTIONS = 50;
const SCAN_MAX_MINTS = 20;

/** The native-SOL pseudo-mint the scan endpoint matches on lamport changes (wrapped SOL ends in …112). */
const NATIVE_SOL_SCAN_MINT = 'So11111111111111111111111111111111111111111';

/** SPL Token and Token-2022 tags: set_authority, mint_to, freeze_account, mint_to_checked. */
const TOKEN_DISCRIMINATORS = ['0x06', '0x07', '0x0a', '0x0e'];
/** Token-2022 extension prefix + sub-instruction, matching MINT_EXTENSION_UPDATES. */
const TOKEN_2022_EXTENSION_DISCRIMINATORS = [
    '0x1a02', // transfer_fee_extension.withdraw_withheld_tokens_from_mint
    '0x1a05', // transfer_fee_extension.set_transfer_fee
    '0x1b01', // confidential_transfer_extension.update_mint
    '0x1c01', // default_account_state_extension.update
    '0x2101', // interest_bearing_mint_extension.update_rate
    '0x2401', // transfer_hook_extension.update
    '0x2b01', // scaled_ui_amount_extension.update_multiplier
    '0x2c01', // pausable_extension.pause
    '0x2c02', // pausable_extension.resume
];

/** By program: instruction names for Parsed Streams and discriminators for Parsed Events. */
const CUSTODY_INSTRUCTIONS = {
    [PROGRAMS.stake]: {
        names: ['authorize', 'authorize_checked', 'authorize_with_seed', 'authorize_checked_with_seed', 'set_lockup', 'set_lockup_checked'],
        discriminators: ['0x01000000', '0x06000000', '0x08000000', '0x0a000000', '0x0b000000', '0x0c000000'],
    },
    [PROGRAMS.splToken]: { names: ['approve', 'approve_checked', 'set_authority'], discriminators: ['0x04', '0x06', '0x0d'] },
    [PROGRAMS.token2022]: { names: ['approve', 'approve_checked', 'set_authority'], discriminators: ['0x04', '0x06', '0x0d'] },
    [PROGRAMS.system]: { names: ['assign', 'assign_with_seed'], discriminators: ['0x01000000', '0x0a000000'] },
} as const;

/** Share of a discovered vault's holding that alerts when it leaves in one transaction. */
const VAULT_OUTFLOW_SHARE = 0.2;
const VAULT_WINDOW_MINUTES = 60;

export function buildTargets(config: Config, discovery: Discovery, state?: StateStore, slotMs = FALLBACK_SLOT_MS): WatchTargets {
    const targets: WatchTargets = {
        programs: new Map(),
        programsByProgramData: new Map(),
        multisigs: new Map(),
        mints: new Map(),
        treasuries: new Map(),
        seizableAccounts: new Map(),
        privilegedKeys: new Map(),
        custodyKeys: new Map(),
        groups: new Map(),
    };
    const addKey = (address: string | null, role: string, subject: string, subjectLabel: string) => {
        if (address && !targets.privilegedKeys.has(address)) targets.privilegedKeys.set(address, { address, role, subject, subjectLabel });
    };
    const addMultisig = (multisig: SquadsMultisig, label: string, group: string) => {
        if (targets.multisigs.has(multisig.address)) return;
        targets.multisigs.set(multisig.address, watchedMultisig(multisig, label));
        targets.groups.set(multisig.address, group);
        for (const member of multisig.members) addKey(member.key, `Member of ${label}`, multisig.address, label);
        addKey(multisig.configAuthority, `Config authority of ${label}`, multisig.address, label);
    };
    const windowSlots = (minutes: number) => Math.round((minutes * 60_000) / slotMs);

    for (const program of config.programs) {
        const discovered = discovery.programs.find((p) => p.programId === program.id);
        const label = program.name ?? short(program.id);
        const watched = {
            id: program.id,
            label,
            programData: discovered?.programData ?? null,
            privilegedInstructions: new Set(program.privilegedInstructions.map(normalizeName)),
            instructionsByDiscriminator: new Map(Object.entries(discovered?.idl?.discriminators ?? {})),
            adminKeys: [...new Set([...program.adminKeys, ...(discovered?.admins.map((a) => a.key) ?? [])])],
        };
        targets.programs.set(program.id, watched);
        targets.groups.set(program.id, program.id);
        if (watched.programData) targets.programsByProgramData.set(watched.programData, watched);
        if (discovered?.multisig) addMultisig(discovered.multisig, `${label} upgrade multisig`, program.id);
        addKey(discovered?.upgradeAuthority ?? null, `Upgrade authority of ${label}`, program.id, label);
        for (const admin of discovered?.admins ?? []) {
            if (admin.multisig) addMultisig(admin.multisig, `${label} admin multisig`, program.id);
            addKey(admin.key, `Admin (${admin.role}) of ${label}`, program.id, label);
        }
        for (const key of program.adminKeys) addKey(key, `Admin of ${label}`, program.id, label);
        if (program.watchVaults) {
            for (const vault of discovered?.vaults ?? []) {
                targets.treasuries.set(vault.authority, vaultTreasury(vault, `${label} vault`, windowSlots(VAULT_WINDOW_MINUTES)));
                targets.groups.set(vault.authority, program.id);
            }
        }
        for (const name of watched.privilegedInstructions) {
            for (const signer of state?.knownSigners(`${program.id}:${name}`) ?? []) {
                addKey(signer, `Admin signer of ${label}`, program.id, label);
            }
        }
    }
    for (const multisig of config.multisigs) {
        const discovered = discovery.multisigs.find((m) => m.address === multisig.address);
        const label = multisig.label ?? short(multisig.address);
        if (discovered) addMultisig(discovered, label, multisig.address);
        else if (!targets.multisigs.has(multisig.address)) {
            targets.multisigs.set(multisig.address, {
                address: multisig.address,
                label,
                version: null,
                threshold: null,
                timeLockSeconds: null,
            });
            targets.groups.set(multisig.address, multisig.address);
        }
    }
    for (const mint of config.mints) {
        const discovered = discovery.mints.find((m) => m.address === mint.address);
        const label = mint.label ?? short(mint.address);
        targets.mints.set(mint.address, {
            address: mint.address,
            label,
            supply: discovered?.supply ?? null,
            decimals: discovered?.decimals ?? null,
            permanentDelegate: discovered?.permanentDelegate ?? null,
        });
        targets.groups.set(mint.address, mint.address);
        addKey(discovered?.mintAuthority ?? null, `Mint authority of ${label}`, mint.address, label);
        addKey(discovered?.freezeAuthority ?? null, `Freeze authority of ${label}`, mint.address, label);
        addKey(discovered?.permanentDelegate ?? null, `Permanent delegate of ${label}`, mint.address, label);
    }
    for (const treasury of config.treasuries) {
        const label = treasury.label ?? short(treasury.address);
        targets.treasuries.set(treasury.address, {
            address: treasury.address,
            label,
            thresholds: new Map(Object.entries(treasury.thresholds)),
            alertOnAnyOutflow: treasury.alertOnAnyOutflow,
            windowSlots: windowSlots(treasury.windowMinutes),
            allowedDestinations: new Set(treasury.allowedDestinations),
            discovered: false,
            tokenAccounts: new Set(),
            delegates: new Map(),
        });
        targets.groups.set(treasury.address, treasury.address);
        targets.custodyKeys.set(treasury.address, { address: treasury.address, label, subject: treasury.address, subjectLabel: label });
    }
    for (const key of config.watchedKeys) {
        const label = key.label ?? short(key.address);
        addKey(key.address, label, key.address, label);
        targets.groups.set(key.address, key.address);
        if (!targets.custodyKeys.has(key.address))
            targets.custodyKeys.set(key.address, { address: key.address, label, subject: key.address, subjectLabel: label });
    }
    for (const account of discovery.tokenAccounts) {
        const treasury = targets.treasuries.get(account.owner);
        if (!treasury) continue;
        treasury.tokenAccounts.add(account.address);
        if (account.delegate) treasury.delegates.set(account.address, account.delegate);
        if (account.permanentDelegate) {
            targets.seizableAccounts.set(account.address, {
                tokenAccount: account.address,
                mint: account.mint,
                delegate: account.permanentDelegate,
                owner: account.owner,
            });
        }
    }
    return targets;
}

/** Each watched permanent delegate, with one subject whose tokens it can take. */
function permanentDelegates(targets: WatchTargets): Map<string, string> {
    const delegates = new Map<string, string>();
    for (const mint of targets.mints.values()) {
        if (mint.permanentDelegate && !delegates.has(mint.permanentDelegate)) delegates.set(mint.permanentDelegate, mint.address);
    }
    for (const account of targets.seizableAccounts.values()) {
        if (!delegates.has(account.delegate)) delegates.set(account.delegate, account.owner);
    }
    return delegates;
}

/** Thresholds are in UI units, like hand-set ones. */
function vaultTreasury(vault: Vault, label: string, windowSlots: number): WatchedTreasury {
    const thresholds = new Map<string, number>();
    for (const holding of vault.holdings) {
        const share = (holding.amount * BigInt(Math.round(VAULT_OUTFLOW_SHARE * 10_000))) / 10_000n;
        if (share > 0n) thresholds.set(holding.mint, Number(formatAmount(share, holding.decimals).replace(/,/g, '')));
    }
    return {
        address: vault.authority,
        label,
        thresholds,
        alertOnAnyOutflow: false,
        windowSlots,
        allowedDestinations: new Set(),
        discovered: true,
        tokenAccounts: new Set(),
        delegates: new Map(),
    };
}

function watchedMultisig(multisig: SquadsMultisig, label: string): WatchedMultisig {
    return {
        address: multisig.address,
        label,
        version: multisig.version,
        threshold: multisig.threshold,
        timeLockSeconds: multisig.timeLockSeconds,
    };
}

export function watchedSubjects(targets: WatchTargets): Set<string> {
    return new Set([
        ...targets.programs.keys(),
        ...targets.multisigs.keys(),
        ...targets.mints.keys(),
        ...targets.treasuries.keys(),
        ...[...targets.privilegedKeys.values()].map((k) => k.subject),
    ]);
}

export function scanPlans(config: Config, targets: WatchTargets): ScanPlan[] {
    const plans: ScanPlan[] = [];
    for (const program of targets.programs.values()) {
        if (program.programData) {
            plans.push({
                key: `programdata:${program.programData}`,
                label: `${program.label} deployments`,
                address: program.programData,
                match: { programs: [{ programId: PROGRAMS.bpfLoaderUpgradeable, scope: 'address' }] },
                status: 'succeeded',
                detectors: ['program-deployment', 'attack-chain'],
                subject: program.id,
            });
        }
        const privileged = config.programs.find((p) => p.id === program.id)?.privilegedInstructions ?? [];
        for (const key of program.adminKeys) {
            plans.push({
                key: `adminkey:${program.id}:${key}`,
                label: `${program.label} admin ${short(key)}`,
                address: key,
                match: { programs: [{ programId: program.id, scope: 'transaction' }] },
                status: 'any',
                detectors: [...(privileged.length > 0 ? ['privileged-instruction'] : []), 'admin-key-behavior', 'attack-chain'],
                subject: program.id,
            });
        }
        chunk(privileged, SCAN_MAX_INSTRUCTIONS).forEach((instructions, i) => {
            plans.push({
                key: `privileged:${program.id}:${i}`,
                label: `${program.label} admin instructions`,
                address: program.id,
                match: { programs: [{ programId: program.id, instructions, scope: 'transaction' }] },
                status: 'any',
                detectors: ['privileged-instruction', 'attack-chain'],
                subject: program.id,
            });
        });
    }
    for (const multisig of targets.multisigs.values()) {
        plans.push({
            key: `multisig:${multisig.address}`,
            label: multisig.label,
            address: multisig.address,
            match: { programs: SQUADS_PROGRAMS.map((programId) => ({ programId, scope: 'address' as const })) },
            status: 'succeeded',
            detectors: ['multisig-change', 'upgrade-proposal', 'multisig-proposal'],
            subject: multisig.address,
        });
    }
    for (const mint of targets.mints.values()) {
        plans.push({
            key: `mint:${mint.address}`,
            label: `${mint.label} mint`,
            address: mint.address,
            match: {
                programs: [
                    { programId: PROGRAMS.splToken, discriminators: TOKEN_DISCRIMINATORS, scope: 'address' },
                    {
                        programId: PROGRAMS.token2022,
                        discriminators: [...TOKEN_DISCRIMINATORS, ...TOKEN_2022_EXTENSION_DISCRIMINATORS],
                        scope: 'address',
                    },
                ],
            },
            status: 'succeeded',
            detectors: ['mint-authority'],
            subject: mint.address,
        });
    }
    for (const treasury of targets.treasuries.values()) {
        const mints = [...treasury.thresholds.keys()].map((m) => (m === 'SOL' ? NATIVE_SOL_SCAN_MINT : m));
        const matches =
            treasury.alertOnAnyOutflow || mints.length === 0
                ? [
                      {
                          programs: [PROGRAMS.system, PROGRAMS.splToken, PROGRAMS.token2022].map((programId) => ({
                              programId,
                              scope: 'address' as const,
                          })),
                      },
                  ]
                : chunk(mints, SCAN_MAX_MINTS).map((group) => ({ mints: group.map((mint) => ({ mint, scope: 'address' as const })) }));
        matches.forEach((match, i) => {
            plans.push({
                key: `treasury:${treasury.address}:${i}`,
                label: treasury.discovered ? `${treasury.label} ${short(treasury.address)} outflows` : `${treasury.label} outflows`,
                address: treasury.address,
                match,
                status: 'succeeded',
                tokenAccounts: 'balanceChanged',
                detectors: ['treasury-outflow'],
                subject: treasury.address,
                ...(treasury.discovered ? { skipFirstScan: true as const } : {}),
            });
        });
    }
    for (const [delegate, subject] of permanentDelegates(targets)) {
        plans.push({
            key: `delegate:${delegate}`,
            label: `Permanent delegate ${short(delegate)}`,
            address: delegate,
            match: {
                programs: [
                    {
                        programId: PROGRAMS.token2022,
                        discriminators: [...DELEGATE_MOVES.values()].map((m) => m.discriminator),
                        scope: 'address',
                    },
                ],
            },
            status: 'succeeded',
            detectors: ['permanent-delegate'],
            subject,
        });
    }
    for (const key of targets.custodyKeys.values()) {
        plans.push({
            key: `custody:${key.address}`,
            label: `${key.label} authority changes`,
            address: key.address,
            match: {
                programs: Object.entries(CUSTODY_INSTRUCTIONS).map(([programId, { discriminators }]) => ({
                    programId,
                    discriminators: [...discriminators],
                    scope: 'address' as const,
                })),
            },
            status: 'succeeded',
            detectors: ['key-authority'],
            subject: key.subject,
        });
    }
    return plans;
}

export function subscriptions(config: Config, targets: WatchTargets): Subscription[] {
    const subs: Subscription[] = [];
    const loaderAccounts = [...targets.programs.values()].flatMap((p) => [p.id, ...(p.programData ? [p.programData] : [])]);
    for (const include of chunk(loaderAccounts, STREAM_MAX_INCLUDED_ACCOUNTS)) {
        subs.push({ label: 'deployments', filter: { programs: [PROGRAMS.bpfLoaderUpgradeable], accounts: { include } } });
    }
    for (const program of config.programs) {
        for (const instructionNames of chunk(program.privilegedInstructions, STREAM_MAX_INSTRUCTION_NAMES)) {
            subs.push({ label: `admin:${program.id}`, filter: { programs: [program.id], instructionNames, includeFailed: true } });
        }
        for (const include of chunk(targets.programs.get(program.id)?.adminKeys ?? [], STREAM_MAX_INCLUDED_ACCOUNTS)) {
            subs.push({ label: `adminkeys:${program.id}`, filter: { programs: [program.id], accounts: { include } } });
        }
    }
    for (const include of chunk([...targets.multisigs.keys()], STREAM_MAX_INCLUDED_ACCOUNTS)) {
        subs.push({ label: 'multisigs', filter: { programs: [...SQUADS_PROGRAMS], accounts: { include } } });
    }
    const mintInstructions = ['set_authority', 'mint_to', 'mint_to_checked', 'freeze_account', ...MINT_EXTENSION_UPDATES.keys()];
    for (const include of chunk([...targets.mints.keys()], STREAM_MAX_INCLUDED_ACCOUNTS)) {
        subs.push({
            label: 'mints',
            filter: { programs: [PROGRAMS.splToken, PROGRAMS.token2022], instructionNames: mintInstructions, accounts: { include } },
        });
    }
    const treasuryAccounts = [...targets.treasuries.values()].flatMap((t) => [t.address, ...t.delegates.keys()]);
    for (const include of chunk(treasuryAccounts, STREAM_MAX_INCLUDED_ACCOUNTS)) {
        subs.push({ label: 'treasuries', filter: { accounts: { include } } });
    }
    for (const include of chunk([...permanentDelegates(targets).keys()], STREAM_MAX_INCLUDED_ACCOUNTS)) {
        subs.push({
            label: 'delegates',
            filter: { programs: [PROGRAMS.token2022], instructionNames: [...DELEGATE_MOVES.keys()], accounts: { include } },
        });
    }
    const custodyNames = [...new Set(Object.values(CUSTODY_INSTRUCTIONS).flatMap((c) => c.names))];
    for (const include of chunk([...targets.custodyKeys.keys()], STREAM_MAX_INCLUDED_ACCOUNTS)) {
        subs.push({
            label: 'custody',
            filter: { programs: Object.keys(CUSTODY_INSTRUCTIONS), instructionNames: custodyNames, accounts: { include } },
        });
    }
    if (targets.privilegedKeys.size > 0) {
        // The authority is an instruction argument, not an account, so this is chain-wide and filtered locally.
        subs.push({
            label: 'nonces',
            filter: { programs: [PROGRAMS.system], instructionNames: ['initialize_nonce_account', 'authorize_nonce_account'] },
        });
    }
    if (subs.length > STREAM_MAX_SUBSCRIPTIONS) {
        throw new Error(
            `This config needs ${subs.length} Parsed Streams subscriptions; one connection allows ${STREAM_MAX_SUBSCRIPTIONS}. Split it across several watchtower.yaml files.`,
        );
    }
    return subs;
}

function chunk<T>(items: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
    return chunks;
}
