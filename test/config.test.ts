import { readFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { address, getAddressEncoder } from '@solana/kit';
import { describe, expect, it } from 'vitest';
import { checkConfigChanges } from '../src/configWatch.js';
import { PROGRAMS } from '../src/constants.js';
import type { ParsedTransactionResult } from 'helius-sdk/parsedEvents/types';
import { namesType, summarizeIdl, type ConfigLayout } from '../src/discover/idl.js';
import { decodeConfig, discoverAdmins, discoverConfigAccounts, fetchIdl, type ConfigAccount } from '../src/discover/index.js';
import { Engine } from '../src/engine.js';
import type { ParsedEventsClient } from '../src/helius/parsedEvents.js';
import type { RpcClient } from '../src/helius/rpc.js';
import type { Runtime } from '../src/runtime.js';
import { context, KEYS } from './helpers.js';

/** Drift's `State` and Kamino's `LendingMarket` and `GlobalConfig`, trimmed from their mainnet IDLs. */
const idl = summarizeIdl(JSON.parse(readFileSync(new URL('./fixtures/idl-config-accounts.json', import.meta.url), 'utf8')));
const state = idl.configLayouts.find((l) => l.account === 'State')!;
const ADMIN = 'H7PiGqqUaanBovwKgEtreJbKmQe6dbq6VTrw6guy7ZgL';
const COUNCIL = 'GzFgdRJXmawPhGeBsyRCDLx4jAKPsvbUqoqitzppkzkW';
const PUMP_AMM = 'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA';
/** Pump AMM's `GlobalConfig`, at the PDA of seed `global_config` on mainnet. */
const PUMP_AMM_GLOBAL_CONFIG = 'ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw';

/** An account's leading bytes: an 8-byte discriminator, then one key. */
function keyed(discriminatorHex: string, key: string): Uint8Array {
    const data = new Uint8Array(40);
    data.set(Buffer.from(discriminatorHex, 'hex'));
    data.set(getAddressEncoder().encode(address(key)), 8);
    return data;
}

function sampledEvents(results: ParsedTransactionResult[]): ParsedEventsClient {
    return {
        async *scanAll() {
            yield* results;
        },
    } as unknown as ParsedEventsClient;
}

/** A Parsed Events result for one `swap` on `KEYS.program` against `pool`. */
function swapOn(pool: string): ParsedTransactionResult {
    return {
        signature: `swap-${pool}`,
        parserStatus: 'OK',
        parsed: {
            slot: 1,
            blockTime: 1_790_000_000,
            fee: 5_000,
            feePayer: KEYS.member,
            transactionStatus: 'OK',
            summary: null,
            nativeTransfers: [],
            tokenTransfers: [],
            instructions: [
                {
                    instructionIndex: 0,
                    innerInstructionIndex: null,
                    stackHeight: 1,
                    programId: KEYS.program,
                    programName: 'whirlpool',
                    instructionName: 'swap',
                    rawAccounts: [],
                    rawData: '',
                    summary: null,
                    decoded: { args: {}, accounts: [{ name: 'whirlpool', pubkey: pool, isSigner: false, isWritable: true }] },
                },
            ],
        },
    } as unknown as ParsedTransactionResult;
}

function stateData(admin: string, fields: Record<string, number> = {}): Uint8Array {
    const data = new Uint8Array(state.length);
    data.set(getAddressEncoder().encode(address(admin)), 8);
    const view = new DataView(data.buffer);
    for (const [name, value] of Object.entries(fields)) {
        const field = state.fields.find((f) => f.name === name)!;
        if (field.type === 'u8') view.setUint8(field.offset, value);
        if (field.type === 'u16') view.setUint16(field.offset, value, true);
        if (field.type === 'u64') view.setBigUint64(field.offset, BigInt(value), true);
    }
    return data;
}

describe('config account layouts', () => {
    it('reads fields only where Borsh and zero-copy layouts agree', () => {
        expect(state.fields.find((f) => f.admin)).toMatchObject({ name: 'admin', offset: 8 });
        expect(state.fields.find((f) => f.name === 'exchangeStatus')).toMatchObject({ offset: 974, type: 'u8' });
        const market = idl.configLayouts.find((l) => l.account === 'LendingMarket')!;
        expect(market.fields.filter((f) => f.admin).map((f) => [f.name, f.offset])).toEqual([
            ['lendingMarketOwner', 24],
            ['lendingMarketOwnerCached', 56],
        ]);
        expect(
            idl.configLayouts
                .find((l) => l.account === 'GlobalConfig')!
                .fields.filter((f) => f.admin)
                .map((f) => f.name),
        ).toEqual(['globalAdmin']);
        expect(idl.configLayouts.map((l) => l.account)).not.toContain('UserState');
    });

    it('reads a config account at its constant-seed PDA instead of scanning a busy program', async () => {
        const pump = summarizeIdl(JSON.parse(readFileSync(new URL('./fixtures/idl-pump-amm.json', import.meta.url), 'utf8')));
        const global = pump.configLayouts.find((l) => l.account === 'GlobalConfig')!;
        expect(global.pdas).toEqual([{ seeds: [Buffer.from('global_config').toString('hex')], program: null }]);
        expect(pump.configLayouts.find((l) => l.account === 'SharingConfig')).toMatchObject({ pdas: [], perEntity: true });

        const data = new Uint8Array(global.length);
        data.set(Buffer.from(global.discriminator, 'hex'));
        data.set(getAddressEncoder().encode(address(ADMIN)), 8);
        const requested: string[][] = [];
        const rpc = {
            getMultipleAccountsData: async (addresses: string[]) => (requested.push(addresses), { slot: 1, data: [data] }),
            getAccountSlices: async () => ({ slices: [], more: true }),
        } as unknown as RpcClient;
        const { accounts } = await discoverConfigAccounts(rpc, sampledEvents([]), PUMP_AMM, pump);
        expect(requested).toEqual([[PUMP_AMM_GLOBAL_CONFIG]]);
        expect(accounts).toMatchObject([{ address: PUMP_AMM_GLOBAL_CONFIG, values: { admin: ADMIN } }]);
    });

    describe('when the stored IDL has instructions only', () => {
        const DRIFT = 'dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH';
        /** Drift's Anchor IDL account on mainnet. */
        const DRIFT_IDL_ACCOUNT = '8BKPjRu7Hvd6Y2J67EdLx9MsrZFQwEMVwYg7NeVbAPF8';
        /** Drift's `State` and the types it uses, trimmed from its on-chain IDL (v2.150.0). */
        const onChain = readFileSync(new URL('./fixtures/idl-drift-onchain.json', import.meta.url));
        const idlAccountData = (json: Buffer) => {
            const compressed = deflateSync(json);
            const header = Buffer.alloc(44);
            header.writeUInt32LE(compressed.length, 40);
            return Buffer.concat([header, compressed]);
        };
        const events = {
            listIdlVersions: async () => [{ slot: 100 }],
            getIdl: async () => ({
                instructions: [{ name: 'update_admin', accounts: [{ name: 'admin', signer: true }, { name: 'state' }] }],
            }),
        } as unknown as ParsedEventsClient;
        const rpcWith = (owner: string) =>
            ({
                getAccountInfo: async (account: string) =>
                    account === DRIFT_IDL_ACCOUNT ? { owner, lamports: 1, executable: false, data: idlAccountData(onChain) } : null,
            }) as unknown as RpcClient;

        it('reads account layouts from the program’s on-chain Anchor IDL', async () => {
            const summary = await fetchIdl(events, DRIFT, undefined, rpcWith(DRIFT));
            expect(summary!.privileged).toEqual(['update_admin']);
            expect(summary!.configLayouts.find((l) => l.account === 'State')!.fields.find((f) => f.admin)).toMatchObject({
                name: 'admin',
                offset: 8,
            });
        });

        it('ignores an IDL account the program does not own', async () => {
            const summary = await fetchIdl(events, DRIFT, undefined, rpcWith(KEYS.attacker));
            expect(summary!.configLayouts).toEqual([]);
        });
    });

    it('matches an account or field name to the type it refers to', () => {
        expect(namesType('marginfi_group', 'MarginfiGroup')).toBe(true);
        expect(namesType('group', 'MarginfiGroup')).toBe(true);
        expect(namesType('whirlpoolsConfig', 'WhirlpoolsConfig')).toBe(true);
        expect(namesType('whirlpool', 'WhirlpoolsConfig')).toBe(false);
        expect(namesType('fig', 'GlobalConfig')).toBe(false);
    });

    describe('on a program too large to list', () => {
        const CONFIG_DISCRIMINATOR = 'aaaaaaaaaaaaaaaa';
        const POOL_DISCRIMINATOR = 'bbbbbbbbbbbbbbbb';
        const layout: ConfigLayout = {
            account: 'WhirlpoolsConfig',
            discriminator: CONFIG_DISCRIMINATOR,
            fields: [{ name: 'fee_authority', offset: 8, type: 'pubkey', admin: true }],
            length: 40,
            pdas: [],
            perEntity: false,
            referencedBy: [{ account: 'Whirlpool', discriminator: POOL_DISCRIMINATOR, offset: 8 }],
        };
        const [busyPool, quietPool, otherPool] = [KEYS.vault, KEYS.treasury, KEYS.nonce];
        const [mainConfig, otherConfig] = [KEYS.configTx, KEYS.proposal];
        const accountsData = new Map([
            [busyPool, keyed(POOL_DISCRIMINATOR, mainConfig)],
            [quietPool, keyed(POOL_DISCRIMINATOR, mainConfig)],
            [otherPool, keyed(POOL_DISCRIMINATOR, otherConfig)],
            [mainConfig, keyed(CONFIG_DISCRIMINATOR, ADMIN)],
            [otherConfig, keyed(CONFIG_DISCRIMINATOR, COUNCIL)],
        ]);
        const rpc = {
            getAccountSlices: async () => ({ slices: [], more: true }),
            getMultipleAccountsData: async (addresses: string[]) => ({ slot: 1, data: addresses.map((a) => accountsData.get(a) ?? null) }),
        } as unknown as RpcClient;
        const idlWith = { instructions: [], privileged: [], discriminators: {}, configLayouts: [layout] };

        it('finds the config most recent transactions use, through the pools that point at it', async () => {
            const swaps = [busyPool, busyPool, busyPool, busyPool, quietPool, otherPool].map((pool) => swapOn(pool));
            const { accounts, unlocated } = await discoverConfigAccounts(rpc, sampledEvents(swaps), KEYS.program, idlWith);
            expect(accounts).toMatchObject([{ address: mainConfig, values: { fee_authority: ADMIN } }]);
            expect(unlocated).toEqual([]);
        });

        it('reports a config type it could neither list nor find in recent transactions', async () => {
            const { accounts, unlocated } = await discoverConfigAccounts(rpc, sampledEvents([]), KEYS.program, idlWith);
            expect(accounts).toEqual([]);
            expect(unlocated).toEqual(['WhirlpoolsConfig']);
        });
    });

    it('decodes keys and integers', () => {
        const values = decodeConfig(stateData(ADMIN, { exchangeStatus: 3, numberOfMarkets: 40 }), state);
        expect(values).toMatchObject({ admin: ADMIN, exchangeStatus: '3', numberOfMarkets: '40' });
    });
});

describe('config-change', () => {
    function runtimeWith(data: () => Uint8Array, slot: () => number = () => 500): Runtime {
        const ctx = context();
        const account: ConfigAccount = { address: KEYS.configTx, layout: state, values: {} };
        return {
            ctx,
            state: ctx.state,
            engine: new Engine(ctx, []),
            discovery: { programs: [{ programId: KEYS.program, configAccounts: [account] }], mints: [], multisigs: [] },
            rpc: { getMultipleAccountsData: async () => ({ slot: slot(), data: [data()] }) },
        } as unknown as Runtime;
    }

    it('sets a baseline, then alerts when the admin changes, linking it as a takeover step', async () => {
        let current = stateData(COUNCIL, { numberOfMarkets: 40 });
        const runtime = runtimeWith(() => current);
        expect(await checkConfigChanges(runtime, 'silent')).toBe(0);

        current = stateData(ADMIN, { numberOfMarkets: 41 });
        expect(await checkConfigChanges(runtime, 'silent')).toBe(1);
        const [finding] = runtime.state.findings();
        expect(finding).toMatchObject({
            detector: 'config-change',
            severity: 'critical',
            title: 'Admin changed in State.admin',
            subject: KEYS.program,
            stages: ['control'],
        });
        expect(finding!.details.admin).toBe(`${COUNCIL} → ${ADMIN}`);
        expect(finding!.details.numberOfMarkets).toBeUndefined();
    });

    it('ignores a read from an older slot than the last one, so a lagging node cannot reverse a change', async () => {
        let current = stateData(COUNCIL);
        let slot = 500;
        const runtime = runtimeWith(
            () => current,
            () => slot,
        );
        await checkConfigChanges(runtime, 'silent');
        current = stateData(ADMIN);
        slot = 510;
        await checkConfigChanges(runtime, 'silent');
        current = stateData(COUNCIL);
        slot = 505;
        await checkConfigChanges(runtime, 'silent');
        expect(runtime.state.findings().map((f) => f.details.admin)).toEqual([`${COUNCIL} → ${ADMIN}`]);
    });

    it('treats a status flip as a risk change and ignores counters', async () => {
        let current = stateData(COUNCIL, { exchangeStatus: 0, numberOfSubAccounts: 1 });
        const runtime = runtimeWith(() => current);
        await checkConfigChanges(runtime, 'silent');
        current = stateData(COUNCIL, { exchangeStatus: 0, numberOfSubAccounts: 2 });
        expect(await checkConfigChanges(runtime, 'silent')).toBe(0);
        current = stateData(COUNCIL, { exchangeStatus: 1, numberOfSubAccounts: 2 });
        await checkConfigChanges(runtime, 'silent');
        expect(runtime.state.findings()[0]).toMatchObject({ severity: 'high', title: 'State settings changed', stages: ['risk'] });
    });
});

describe('discoverAdmins', () => {
    const pump = summarizeIdl(JSON.parse(readFileSync(new URL('./fixtures/idl-pump-amm.json', import.meta.url), 'utf8')));
    const globalConfig = pump.configLayouts.find((l) => l.account === 'GlobalConfig')!;

    /** Admin keys when the config account's `admin` is `admin`, `KEYS.member` signed as admin, and an earlier run kept `COUNCIL`. */
    async function adminKeys(layout: ConfigLayout, admin: string): Promise<string[]> {
        const config: ConfigAccount = { address: KEYS.configTx, layout, values: { admin } };
        const call = swapOn(KEYS.program);
        Object.assign(call.parsed!.instructions[0]!, {
            instructionName: 'update_admin',
            decoded: { args: {}, accounts: [{ name: 'admin', pubkey: KEYS.member, isSigner: true, isWritable: false }] },
        });
        const admins = await discoverAdmins(
            {} as RpcClient,
            sampledEvents([call]),
            KEYS.program,
            [config],
            ['update_admin'],
            new Map([[COUNCIL, 'admin']]),
        );
        return admins.map((a) => a.key);
    }

    it('drops past signers of a role the config account at a constant-seed PDA now gives to another key', async () => {
        expect(await adminKeys(globalConfig, ADMIN)).toEqual([ADMIN]);
    });

    it('drops past signers of a renounced role', async () => {
        expect(await adminKeys(globalConfig, PROGRAMS.system)).toEqual([]);
    });

    it('keeps the signers when the config account’s admin key is dropped as an unknown PDA', async () => {
        expect(await adminKeys(globalConfig, PUMP_AMM_GLOBAL_CONFIG)).toEqual([KEYS.member, COUNCIL]);
    });

    it('keeps the signers when the config type can have accounts discovery did not find', async () => {
        expect(await adminKeys(state, ADMIN)).toEqual([ADMIN, KEYS.member, COUNCIL]);
        expect(await adminKeys({ ...globalConfig, perEntity: true }, ADMIN)).toEqual([ADMIN, KEYS.member, COUNCIL]);
    });
});
