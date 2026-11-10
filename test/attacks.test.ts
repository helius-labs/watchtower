import { createHash } from 'node:crypto';
import { address, getAddressEncoder } from '@solana/kit';
import { describe, expect, it } from 'vitest';
import { parseConfig, type Config } from '../src/config.js';
import { PROGRAMS } from '../src/constants.js';
import { detect } from '../src/detectors/index.js';
import { Engine } from '../src/engine.js';
import type { Finding } from '../src/detectors/types.js';
import type { BuildCheck } from '../src/discover/build.js';
import type { ProgramState } from '../src/discover/index.js';
import type { ParsedEventsClient } from '../src/helius/parsedEvents.js';
import type { RpcClient } from '../src/helius/rpc.js';
import { assessPosture } from '../src/report/posture.js';
import { buildTargets, scanPlans, subscriptions } from '../src/targets.js';
import { createEnricher, vetAdminSigner, vetListing, vetUpgrade } from '../src/vet.js';
import { context, KEYS, tx, type IxSpec } from './helpers.js';

const encode = getAddressEncoder();
const RECIPIENT = 'Recipient1111111111111111111111111111111111';
const STAKE_ACCOUNT = 'StakeAcct111111111111111111111111111111111';
/** A real Squads vault address; message keys must decode to 32 bytes. */
const VAULT = 'GzFgdRJXmawPhGeBsyRCDLx4jAKPsvbUqoqitzppkzkW';

/** A Squads v4 `TransactionMessage`: u8-length vectors, except instruction data, which has a u16 length. */
function message(keys: string[], instructions: { program: number; accounts: number[]; data: number[] }[]): string {
    const bytes = [1, 1, 1, keys.length, ...keys.flatMap((k) => [...encode.encode(address(k))])];
    bytes.push(instructions.length);
    for (const ix of instructions)
        bytes.push(ix.program, ix.accounts.length, ...ix.accounts, ix.data.length & 0xff, ix.data.length >> 8, ...ix.data);
    bytes.push(0);
    return Buffer.from(bytes).toString('base64');
}

function u64(value: bigint): number[] {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64LE(value);
    return [...buffer];
}

function propose(
    signature: string,
    slot: number,
    proposer: string,
    transactionMessage: string,
    transaction = KEYS.configTx,
): ReturnType<typeof tx> {
    return tx(signature, slot, [
        {
            programId: PROGRAMS.squadsV4,
            name: 'vault_transaction_create',
            accounts: [
                ['multisig', KEYS.multisig],
                ['transaction', transaction],
                ['creator', proposer, true],
            ],
            args: { args: { vault_index: 0, ephemeral_signers: 0, transaction_message: transactionMessage, memo: null } },
        },
        {
            programId: PROGRAMS.squadsV4,
            name: 'proposal_create',
            accounts: [
                ['multisig', KEYS.multisig],
                ['proposal', KEYS.proposal],
                ['creator', proposer, true],
            ],
        },
    ]);
}

const solTransfer = message(
    [VAULT, RECIPIENT, PROGRAMS.system],
    [{ program: 2, accounts: [0, 1], data: [2, 0, 0, 0, ...u64(5_000_000_000n)] }],
);

const advanceNonce: IxSpec = {
    programId: PROGRAMS.system,
    name: 'advance_nonce_account',
    accounts: [
        ['nonce_account', KEYS.nonce],
        ['nonce_authority', KEYS.attacker, true],
    ],
};

const ofDetector = (findings: Finding[], id: string) => findings.filter((f) => f.detector === id);

describe('multisig-proposal', () => {
    it('decodes what a proposal would do and flags a first-time proposer', () => {
        const ctx = context();
        const [first] = ofDetector(detect(propose('sig-p1', 100, KEYS.member, solTransfer), ctx), 'multisig-proposal');
        expect(first).toMatchObject({ severity: 'medium', title: 'Multisig proposal created' });
        expect(first!.description).toContain(`transfer 5 SOL to ${RECIPIENT}`);
        expect(first!.description).toContain('1 day time lock');

        const [second] = ofDetector(detect(propose('sig-p2', 110, KEYS.attacker, solTransfer, KEYS.buffer), ctx), 'multisig-proposal');
        expect(second).toMatchObject({ severity: 'high', title: 'Proposal from a first-time proposer' });
    });

    it('collapses a v3 proposal built one instruction at a time', () => {
        const ctx = context();
        ctx.targets.multisigs.get(KEYS.multisig)!.version = 3;
        const add = (sig: string) =>
            ofDetector(
                detect(
                    tx(sig, 100, [
                        {
                            programId: PROGRAMS.squadsV3,
                            name: 'add_instruction',
                            accounts: [
                                ['multisig', KEYS.multisig],
                                ['transaction', KEYS.configTx],
                                ['creator', KEYS.member, true],
                            ],
                            args: {
                                incoming_instruction: {
                                    program_id: PROGRAMS.system,
                                    keys: [{ pubkey: VAULT }, { pubkey: RECIPIENT }],
                                    data: Buffer.from([2, 0, 0, 0, ...u64(1_000_000_000n)]).toString('base64'),
                                },
                            },
                        },
                    ]),
                    ctx,
                ),
                'multisig-proposal',
            )[0]!;
        add('v3-1');
        add('v3-2');
        expect(add('v3-3').details['Would do']).toBe(`transfer 1 SOL to ${RECIPIENT} ×3`);
    });

    it('names calls to the watched program from its IDL discriminators', () => {
        const ctx = context({ privileged: ['setAdmin'] });
        const discriminator = createHash('sha256').update('global:set_admin').digest().subarray(0, 8);
        ctx.targets.programs.get(KEYS.program)!.instructionsByDiscriminator.set(discriminator.toString('hex'), 'setAdmin');
        const setAdmin = message([VAULT, KEYS.program], [{ program: 1, accounts: [0], data: [...discriminator] }]);
        const [finding] = ofDetector(detect(propose('sig-admin', 100, KEYS.member, setAdmin), ctx), 'multisig-proposal');
        expect(finding).toMatchObject({ severity: 'high' });
        expect(finding!.details['Would do']).toBe('call setAdmin on Test Program (admin-only)');
    });

    it('treats an approval signed against a durable nonce as critical', () => {
        const ctx = context();
        detect(propose('sig-p', 100, KEYS.member, solTransfer), ctx);
        const findings = detect(
            tx('sig-approve', 200, [
                advanceNonce,
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'proposal_approve',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['member', KEYS.member, true],
                        ['proposal', KEYS.proposal],
                    ],
                },
            ]),
            ctx,
        );
        const [approval] = ofDetector(findings, 'multisig-proposal');
        expect(approval).toMatchObject({
            severity: 'critical',
            title: 'Multisig approval signed with a durable nonce',
            stages: ['control'],
        });
        expect(approval!.details['Would do']).toContain('transfer 5 SOL');
    });

    it('escalates an execution that follows its proposal within the hour', () => {
        const ctx = context();
        detect(propose('sig-p', 100, KEYS.member, solTransfer), ctx);
        const execute = (sig: string, slot: number) =>
            ofDetector(
                detect(
                    tx(sig, slot, [
                        {
                            programId: PROGRAMS.squadsV4,
                            name: 'vault_transaction_execute',
                            accounts: [
                                ['multisig', KEYS.multisig],
                                ['proposal', KEYS.proposal],
                                ['transaction', KEYS.configTx],
                                ['member', KEYS.member, true],
                            ],
                        },
                    ]),
                    ctx,
                ),
                'multisig-proposal',
            )[0]!;
        const rushed = execute('sig-x1', 150);
        expect(rushed).toMatchObject({ severity: 'high', title: 'Proposal executed soon after it was created' });
        expect(rushed.description).toContain('transfer 5 SOL');
        expect(execute('sig-x2', 100 + 9_000 * 2)).toMatchObject({ severity: 'medium', title: 'Multisig proposal executed' });
    });

    it('leaves loader changes to watched programs to upgrade-proposal', () => {
        const ctx = context();
        const upgrade = message(
            [VAULT, KEYS.programData, KEYS.program, KEYS.buffer, PROGRAMS.bpfLoaderUpgradeable],
            [{ program: 4, accounts: [1, 2, 3, 0, 0, 0, 0], data: [3, 0, 0, 0] }],
        );
        const findings = detect(propose('sig-up', 100, KEYS.member, upgrade), ctx);
        expect(ofDetector(findings, 'multisig-proposal')).toEqual([]);
        expect(ofDetector(findings, 'upgrade-proposal')).toHaveLength(1);
    });
});

describe('key-authority', () => {
    const stakeAuthorize = (signer: string, role: string): IxSpec => ({
        programId: PROGRAMS.stake,
        name: 'authorize',
        accounts: [
            ['stake_account', STAKE_ACCOUNT],
            ['clock_sysvar', 'SysvarC1ock11111111111111111111111111111111'],
            ['authority', signer, true],
        ],
        args: { new_authorized_pubkey: KEYS.attacker, stake_authorize: role },
    });

    it('flags a withdrawer hand-off hidden in a routine transaction', () => {
        const findings = detect(
            tx('sig-kiln', 100, [
                {
                    programId: PROGRAMS.stake,
                    name: 'deactivate',
                    accounts: [
                        ['stake_account', STAKE_ACCOUNT],
                        ['stake_authority', KEYS.treasury, true],
                    ],
                },
                stakeAuthorize(KEYS.treasury, 'Staker'),
                stakeAuthorize(KEYS.treasury, 'Withdrawer'),
            ]),
            context(),
        );
        const changes = ofDetector(findings, 'key-authority');
        expect(changes.map((f) => [f.severity, f.title])).toEqual([
            ['high', 'Stake staker authority moved'],
            ['critical', 'Stake withdrawer authority moved'],
        ]);
        expect(changes[1]!.details['Bundled with']).toBe('deactivate');
        expect(changes[1]!.description).toContain('2 such changes');
    });

    it('flags token owner changes, delegates and account reassignment', () => {
        const ctx = context();
        const titles = (ix: IxSpec) =>
            ofDetector(detect(tx(`sig-${ix.name}`, 100, [ix]), ctx), 'key-authority').map((f) => [f.severity, f.title]);
        expect(
            titles({
                programId: PROGRAMS.splToken,
                name: 'set_authority',
                accounts: [
                    ['mint_or_account', KEYS.buffer],
                    ['current_authority', KEYS.treasury, true],
                ],
                args: { authority_type: 'accountOwner', new_authority: KEYS.attacker },
            }),
        ).toEqual([['critical', 'Token account ownership transferred']]);
        expect(
            titles({
                programId: PROGRAMS.splToken,
                name: 'approve',
                accounts: [
                    ['source_account', KEYS.buffer],
                    ['delegate', KEYS.attacker],
                    ['owner', KEYS.treasury, true],
                ],
                args: { amount: '1000' },
            }),
        ).toEqual([['high', 'Token delegate approved']]);
        expect(
            titles({
                programId: PROGRAMS.system,
                name: 'assign',
                accounts: [['account', KEYS.treasury, true]],
                args: { owner: KEYS.attacker },
            }),
        ).toEqual([['critical', 'Account reassigned to a program']]);
    });

    it('ignores changes signed by keys it does not protect', () => {
        expect(ofDetector(detect(tx('sig-other', 100, [stakeAuthorize(KEYS.attacker, 'Withdrawer')]), context()), 'key-authority')).toEqual(
            [],
        );
    });
});

describe('treasury sweeps and destinations', () => {
    const MINT_A = 'MintA11111111111111111111111111111111111111';
    const MINT_B = 'MintB11111111111111111111111111111111111111';
    const tokenOut = (mint: string) => ({
        fromUserAccount: KEYS.treasury,
        toUserAccount: KEYS.attacker,
        fromTokenAccount: null,
        toTokenAccount: null,
        rawTokenAmount: 1_000,
        decimals: 0,
        tokenStandard: 'Fungible',
        mint,
    });

    it('raises one critical alert when three assets leave within the window', () => {
        const ctx = context({ thresholds: { SOL: 100 } });
        const sweep = (sig: string, slot: number, mint: string) =>
            ofDetector(detect(tx(sig, slot, [], { tokenTransfers: [tokenOut(mint)] }), ctx), 'treasury-outflow');
        expect(sweep('s1', 100, MINT_A)).toEqual([]);
        expect(sweep('s2', 110, MINT_B)).toEqual([]);
        const third = detect(
            tx('s3', 120, [], {
                nativeTransfers: [{ fromUserAccount: KEYS.treasury, toUserAccount: KEYS.attacker, amount: 200_000_000_000 }],
            }),
            ctx,
        );
        expect(ofDetector(third, 'treasury-outflow').map((f) => f.title)).toEqual(['Large treasury outflow', 'Multi-asset sweep']);
        expect(sweep('s4', 130, KEYS.mint)).toEqual([]);
    });

    it('only counts threshold-sized outflows toward a sweep from a discovered vault', () => {
        const ctx = context();
        Object.assign(ctx.targets.treasuries.get(KEYS.treasury)!, { discovered: true, thresholds: new Map() });
        for (const [i, mint] of [MINT_A, MINT_B, KEYS.mint].entries()) {
            expect(ofDetector(detect(tx(`v${i}`, 100 + i, [], { tokenTransfers: [tokenOut(mint)] }), ctx), 'treasury-outflow')).toEqual([]);
        }
    });

    it('alerts on any outflow to an address outside the allowed list', () => {
        const ctx = context();
        ctx.targets.treasuries.get(KEYS.treasury)!.allowedDestinations.add(RECIPIENT);
        const out = (sig: string, to: string) =>
            ofDetector(
                detect(
                    tx(sig, 100, [], { nativeTransfers: [{ fromUserAccount: KEYS.treasury, toUserAccount: to, amount: 1_000_000 }] }),
                    ctx,
                ),
                'treasury-outflow',
            );
        expect(out('d1', RECIPIENT)).toEqual([]);
        expect(out('d2', KEYS.attacker).map((f) => [f.severity, f.title])).toEqual([['high', 'Outflow to an unlisted destination']]);
    });
});

describe('attack-chain', () => {
    it('links a control change and a risk change before any funds move, then again when funds leave', () => {
        const ctx = context({ privileged: ['setAdmin', 'initializeSpotMarket'], thresholds: { SOL: 100 } });
        const admin = (sig: string, slot: number, name: string) =>
            detect(tx(sig, slot, [{ programId: KEYS.program, name, accounts: [['admin', KEYS.member, true]] }]), ctx);

        expect(ofDetector(admin('c1', 100, 'set_admin'), 'attack-chain')).toEqual([]);
        const [chain] = ofDetector(admin('c2', 200, 'initialize_spot_market'), 'attack-chain');
        expect(chain).toMatchObject({
            severity: 'critical',
            title: 'Possible attack in progress',
            subject: KEYS.program,
            subjectLabel: 'Test Program',
        });
        expect(chain!.description).toContain('Admin control changed: set_admin → New market or asset added: initialize_spot_market');
        expect(ofDetector(admin('c3', 300, 'set_admin'), 'attack-chain')).toEqual([]);

        const drain = detect(
            tx('c4', 400, [], {
                nativeTransfers: [{ fromUserAccount: KEYS.treasury, toUserAccount: KEYS.attacker, amount: 500_000_000_000 }],
            }),
            ctx,
        );
        expect(ofDetector(drain, 'attack-chain')[0]!.description).toContain('funds moved out');
    });

    it('links stages that enrichment adds, such as a new admin wallet on a listing', async () => {
        const ctx = context({ privileged: ['initializeSpotMarket'] });
        const engine = new Engine(ctx, [], undefined, async (f) => {
            if (f.details['Admin signer']) f.stages = [...(f.stages ?? []), 'control'];
        });
        const recorded = await engine.process(
            tx('e1', 100, [
                {
                    programId: KEYS.program,
                    name: 'initialize_spot_market',
                    accounts: [
                        ['admin', KEYS.attacker, true],
                        ['spot_market_mint', KEYS.mint],
                    ],
                },
            ]),
            () => 'silent',
        );
        expect(recorded.map((f) => f.detector)).toEqual(['privileged-instruction', 'attack-chain']);
        expect(recorded[1]!.details['1. risk + control']).toContain('New market or asset added');
    });

    it('does not link stages more than a day apart', () => {
        const ctx = context({ privileged: ['setAdmin', 'initializeSpotMarket'] });
        const admin = (sig: string, slot: number, name: string) =>
            detect(tx(sig, slot, [{ programId: KEYS.program, name, accounts: [['admin', KEYS.member, true]] }]), ctx);
        admin('f1', 100, 'set_admin');
        expect(ofDetector(admin('f2', 100 + 300_000, 'initialize_spot_market'), 'attack-chain')).toEqual([]);
    });
});

describe('listing vetting', () => {
    const listing = (): Finding => ({
        id: 'x',
        detector: 'privileged-instruction',
        severity: 'high',
        title: 'New market or asset added: initialize_spot_market',
        description: 'Listed.',
        subject: KEYS.program,
        subjectLabel: 'Drift',
        signature: 'sig',
        slot: 1,
        blockTime: 1_775_000_000,
        details: { 'Listed mint': KEYS.mint },
    });
    const mintData = new Uint8Array(82);
    new DataView(mintData.buffer).setBigUint64(36, 750_000_000n * 10n ** 6n, true);
    mintData[44] = 6;
    const rpc = {
        getAccountInfo: async () => ({ owner: PROGRAMS.splToken, lamports: 1, executable: false, data: mintData }),
        getTokenLargestAccounts: async () => [700_000_000],
    } as unknown as RpcClient;

    it('makes a listing of a weeks-old token critical', async () => {
        const finding = listing();
        await vetListing(rpc, async () => 1_775_000_000 - 20 * 86_400, finding);
        expect(finding.severity).toBe('critical');
        expect(finding.details['Token age at listing']).toBe('20 days');
        expect(finding.description).toContain('created only 20 days before this listing');
    });

    it('leaves an established token alone and records why vetting failed', async () => {
        const finding = listing();
        await vetListing(rpc, async () => 1_600_000_000, finding);
        expect(finding.severity).toBe('high');

        const failed = listing();
        await vetListing(rpc, () => Promise.reject(new Error('HTTP 500')), failed);
        expect(failed.details.Vetting).toContain('HTTP 500');
    });

    it('flags an admin call from a wallet funded a day earlier, as Drift’s attacker did', async () => {
        const finding: Finding = { ...listing(), details: { 'Admin signer': KEYS.attacker } };
        const flagged = new Set<string>();
        await vetAdminSigner(async () => 1_775_000_000 - 25 * 3_600, finding, flagged);
        expect(finding).toMatchObject({ severity: 'critical', stages: ['control'] });
        expect(finding.title).toMatch(/^Admin call from a new wallet/);
        expect(finding.details['Admin signer age']).toBe('1 day');

        const next: Finding = { ...listing(), stages: ['risk'], details: { 'Admin signer': KEYS.attacker } };
        await vetAdminSigner(async () => 1_775_000_000 - 25 * 3_600, next, flagged);
        expect(next).toMatchObject({ severity: 'high', stages: ['risk', 'control'] });
    });

    it('looks up an address again after a failed lookup', async () => {
        let calls = 0;
        const events = {
            transactionHistory: async () => {
                if (calls++ === 0) throw new Error('HTTP 503');
                return { data: [{ parsed: { blockTime: 1_600_000_000 } }] };
            },
        } as unknown as ParsedEventsClient;
        const enrich = createEnricher(rpc, events, () => null);
        await enrich({ ...listing(), details: { 'Admin signer': KEYS.member } });
        const finding: Finding = { ...listing(), details: { 'Admin signer': KEYS.member } };
        await enrich(finding);
        expect(calls).toBe(2);
        expect(finding.details['Admin signer age']).toBeDefined();
    });

    it('looks up each address once', async () => {
        let calls = 0;
        const events = {
            transactionHistory: async () => {
                calls++;
                return { data: [{ parsed: { blockTime: 1_600_000_000 } }] };
            },
        } as unknown as ParsedEventsClient;
        const enrich = createEnricher(rpc, events, () => null);
        for (let i = 0; i < 3; i++) await enrich({ ...listing(), details: { 'Admin signer': KEYS.member } });
        expect(calls).toBe(1);
    });
});

describe('verified builds', () => {
    const upgrade = (slot: number): Finding => ({
        id: 'u',
        detector: 'program-deployment',
        severity: 'high',
        title: 'Program upgraded',
        description: 'New bytecode was deployed to Kamino Lend.',
        subject: KEYS.program,
        subjectLabel: 'Kamino Lend',
        signature: 'sig',
        slot,
        blockTime: null,
        details: {},
    });
    const build: BuildCheck = {
        hash: 'ab'.repeat(32),
        deploySlot: 100,
        verified: false,
        source: 'https://github.com/Kamino-Finance/klend @ 77e8185',
    };

    it('notes when an upgrade matches its verified build', async () => {
        const finding = upgrade(100);
        await vetUpgrade(async () => ({ ...build, verified: true }), finding);
        expect(finding.details['Verified build']).toBe('Yes, https://github.com/Kamino-Finance/klend @ 77e8185');
    });

    it('says when an upgrade is not the registered build, and skips bytecode a later upgrade replaced', async () => {
        const unverified = upgrade(100);
        await vetUpgrade(async () => build, unverified);
        expect(unverified.details['Verified build']).toMatch(/^No: not https/);
        expect(unverified.description).toContain('may simply not be verified yet');

        const old = upgrade(50);
        await vetUpgrade(async () => build, old);
        expect(old.details['Verified build']).toMatch(/^Not checked/);
    });

    it('grades the deployed build in posture', () => {
        const base = {
            programId: KEYS.program,
            programData: KEYS.programData,
            upgradeAuthority: null,
            authorityKind: 'immutable' as const,
            lastDeploySlot: 1,
            multisig: null,
            idl: null,
            admins: [],
            vaults: [],
            configAccounts: [],
            unlocatedConfigs: [],
        };
        const config = { ...parseConfig({ programs: [{ id: KEYS.program }] }), apiKey: 'k', endpoints: {}, configPath: '' };
        const grade = (b: typeof build | null) =>
            assessPosture(
                config,
                { programs: [{ ...base, build: b }], mints: [], multisigs: [], tokenAccounts: [] },
                { currentSlot: 10, slotMs: 400 },
            ).subjects[0]!.checks.find((c) => /build/i.test(c.title));
        expect(grade({ ...build, verified: true })).toMatchObject({ status: 'pass' });
        expect(grade(build)).toMatchObject({ status: 'warn', title: 'Deployed bytecode does not match its verified build' });
        expect(grade({ ...build, source: null })).toMatchObject({ status: 'warn', title: 'No verified build' });
        expect(grade(null)).toBeUndefined();
    });
});

describe('targets for admins, vaults and custody keys', () => {
    const adminMultisig = {
        version: 4 as const,
        address: KEYS.configTx,
        createKey: KEYS.buffer,
        configAuthority: null,
        threshold: 2,
        timeLockSeconds: 0,
        transactionIndex: 1n,
        members: [],
    };
    const program: ProgramState = {
        programId: KEYS.program,
        programData: KEYS.programData,
        upgradeAuthority: null,
        authorityKind: 'immutable',
        lastDeploySlot: 1,
        multisig: null,
        idl: null,
        admins: [{ key: KEYS.vault, role: 'admin', kind: 'squads', multisig: { ...adminMultisig, vaultIndex: 0 } }],
        vaults: [
            {
                authority: KEYS.nonce,
                usd: 1_000_000,
                holdings: [{ mint: 'SOL', symbol: 'SOL', amount: 2_000_000_000_000n, decimals: 9, usd: 1_000_000 }],
            },
        ],
        build: null,
        configAccounts: [],
        unlocatedConfigs: [],
    };
    const config = {
        ...parseConfig({
            programs: [{ id: KEYS.program, name: 'Drift', privilegedInstructions: ['setAdmin'], watchVaults: true }],
            treasuries: [{ address: KEYS.treasury, thresholds: { SOL: 10 }, allowedDestinations: [RECIPIENT] }],
        }),
        apiKey: 'k',
        endpoints: {},
        configPath: '',
    } satisfies Config;

    it('watches the admin multisig, the vault and the treasury key', () => {
        const targets = buildTargets(config, { programs: [program], mints: [], multisigs: [], tokenAccounts: [] }, undefined, 400);
        expect(targets.multisigs.get(KEYS.configTx)?.label).toBe('Drift admin multisig');
        expect(targets.groups.get(KEYS.configTx)).toBe(KEYS.program);
        expect(targets.treasuries.get(KEYS.nonce)).toMatchObject({
            label: 'Drift vault',
            discovered: true,
            thresholds: new Map([['SOL', 400]]),
        });
        expect(targets.groups.get(KEYS.nonce)).toBe(KEYS.program);
        expect(targets.treasuries.get(KEYS.treasury)?.allowedDestinations).toEqual(new Set([RECIPIENT]));
        expect([...targets.custodyKeys.keys()]).toEqual([KEYS.treasury]);

        const plans = scanPlans(config, targets);
        expect(plans.find((p) => p.key === `custody:${KEYS.treasury}`)?.detectors).toEqual(['key-authority']);
        expect(plans.find((p) => p.key === `multisig:${KEYS.configTx}`)?.detectors).toContain('multisig-proposal');
        expect(subscriptions(config, targets).find((s) => s.label === 'custody')?.filter.accounts?.include).toEqual([KEYS.treasury]);
    });

    it('skips vaults when watchVaults is off', () => {
        const off = { ...config, programs: config.programs.map((p) => ({ ...p, watchVaults: false })) };
        expect(
            buildTargets(off, { programs: [program], mints: [], multisigs: [], tokenAccounts: [] }, undefined, 400).treasuries.has(
                KEYS.nonce,
            ),
        ).toBe(false);
    });

    it('grades the admin multisig in posture', () => {
        const posture = assessPosture(
            config,
            { programs: [program], mints: [], multisigs: [], tokenAccounts: [] },
            { currentSlot: 10, slotMs: 400 },
        );
        const titles = posture.subjects[0]!.checks.map((c) => c.title);
        expect(titles).toContain('Admin actions need 2 of 0 signatures');
        expect(titles).toContain('No time lock');

        const wallet = { ...program, admins: [{ key: KEYS.member, role: 'admin', kind: 'wallet' as const, multisig: null }] };
        const graded = assessPosture(
            config,
            { programs: [wallet], mints: [], multisigs: [], tokenAccounts: [] },
            { currentSlot: 10, slotMs: 400 },
        );
        expect(graded.subjects[0]!.checks.find((c) => c.title === 'Admin key is a single wallet')).toMatchObject({
            status: 'fail',
            penalty: 25,
        });
    });
});
