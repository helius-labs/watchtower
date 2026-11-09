import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { backfill, caughtUp } from '../src/backfill.js';
import type { Config } from '../src/config.js';
import { Engine } from '../src/engine.js';
import type { ParsedEventsClient, ScanProgress, ScanRequest } from '../src/helius/parsedEvents.js';
import type { ParsedTransactionResult } from 'helius-sdk/parsedEvents/types';
import { StateStore } from '../src/state.js';
import { scanPlans, subscriptions, type ScanPlan } from '../src/targets.js';
import { context, KEYS } from './helpers.js';

const config = { backfill: { lookbackDays: 30, maxScannedTransactions: 1_000 } } as Config;

const plan: ScanPlan = {
    key: `programdata:${KEYS.programData}`,
    label: 'Test deployments',
    address: KEYS.programData,
    match: { programs: [] },
    status: 'succeeded',
    detectors: ['program-deployment'],
    subject: KEYS.program,
};

interface FakePage {
    results: ParsedTransactionResult[];
    progress: Partial<ScanProgress>;
    fail?: boolean;
}

function fakeEvents(page: FakePage, requests: ScanRequest[] = []): ParsedEventsClient {
    return {
        async *scanAll(request: ScanRequest, _budget: number, onProgress?: (p: ScanProgress) => void) {
            requests.push(request);
            if (page.fail) throw new Error('HTTP 503');
            onProgress?.({ windowEnded: false, scannedTransactions: 0, matchedTransactions: 0, creditsCharged: 0, ...page.progress });
            yield* page.results;
        },
    } as unknown as ParsedEventsClient;
}

function upgradeResult(signature: string, slot: number): ParsedTransactionResult {
    return {
        signature,
        parserStatus: 'OK',
        parsed: {
            slot,
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
                    programId: 'BPFLoaderUpgradeab1e11111111111111111111111',
                    programName: 'bpf_loader_upgradeable',
                    instructionName: 'upgrade',
                    rawAccounts: [],
                    rawData: '',
                    summary: null,
                    decoded: {
                        args: {},
                        accounts: [
                            { name: 'program_data_account', pubkey: KEYS.programData, isSigner: false, isWritable: true },
                            { name: 'program_account', pubkey: KEYS.program, isSigner: false, isWritable: true },
                            { name: 'authority', pubkey: KEYS.vault, isSigner: true, isWritable: false },
                        ],
                    },
                },
            ],
        },
    };
}

describe('backfill', () => {
    it('records a first scan silently, then alerts on events found by later scans', async () => {
        const ctx = context();
        const engine = new Engine(ctx, []);
        const requests: ScanRequest[] = [];

        await backfill(
            config,
            fakeEvents({ results: [upgradeResult('old', 100)], progress: { windowEnded: true } }, requests),
            engine,
            ctx.state,
            [plan],
            1_000,
            { alertMode: 'queue' },
        );
        expect(requests[0]!.time?.gte).toBeDefined();
        expect(ctx.state.cursor(plan.key)).toEqual({ slot: 1_000, caughtUp: true });
        expect(ctx.state.pendingAlerts()).toEqual([]);

        await backfill(
            config,
            fakeEvents({ results: [upgradeResult('new', 1_500)], progress: { windowEnded: true } }, requests),
            engine,
            ctx.state,
            [plan],
            2_000,
            { alertMode: 'queue' },
        );
        expect(requests[1]!.slot).toEqual({ gt: 1_000, lte: 2_000 });
        expect(requests[1]!.minContextSlot).toBe(2_000);
        expect(ctx.state.pendingAlerts().map((f) => f.signature)).toEqual(['new']);
    });

    it('keeps alerting from a caught-up plan when a new plan for the same program starts', async () => {
        const ctx = context();
        ctx.state.advanceCursor(plan.key, 1_000, true);
        const newAdminKey: ScanPlan = { ...plan, key: `adminkey:${KEYS.program}:${KEYS.member}` };
        const events = {
            async *scanAll(request: ScanRequest) {
                yield upgradeResult(request.time ? 'history' : 'during-outage', request.time ? 900 : 1_500);
            },
        } as unknown as ParsedEventsClient;
        await backfill(config, events, new Engine(ctx, []), ctx.state, [newAdminKey, plan], 2_000, { alertMode: 'queue' });
        expect(ctx.state.pendingAlerts().map((f) => f.signature)).toEqual(['during-outage']);
    });

    it('starts a discovered vault from the present, then gap-fills it like any plan', async () => {
        const ctx = context();
        const requests: ScanRequest[] = [];
        const vault = { ...plan, key: 'treasury:vault:0', skipFirstScan: true as const };
        const [first] = await backfill(
            config,
            fakeEvents({ results: [], progress: { windowEnded: true } }, requests),
            new Engine(ctx, []),
            ctx.state,
            [vault],
            1_000,
            { alertMode: 'send' },
        );
        expect(requests).toEqual([]);
        expect(first).toMatchObject({ coverage: 'complete', findings: 0 });
        expect(ctx.state.cursor(vault.key)).toEqual({ slot: 1_000, caughtUp: true });

        await backfill(
            config,
            fakeEvents({ results: [], progress: { windowEnded: true } }, requests),
            new Engine(ctx, []),
            ctx.state,
            [vault],
            2_000,
            { alertMode: 'send' },
        );
        expect(requests[0]!.slot).toEqual({ gt: 1_000, lte: 2_000 });
    });

    it('scans a first run newest-first and treats it as caught up even when the budget runs out', async () => {
        const ctx = context();
        const requests: ScanRequest[] = [];
        const partial = {
            results: [],
            progress: { windowEnded: false, scannedTransactions: 1_000, scannedThrough: { slot: 700, blockTime: null } },
        };
        const [result] = await backfill(config, fakeEvents(partial, requests), new Engine(ctx, []), ctx.state, [plan], 1_000, {
            alertMode: 'send',
        });
        expect(requests[0]!.sortOrder).toBe('desc');
        expect(result!.coverage).toBe('recent-only');
        expect(caughtUp(result!)).toBe(true);
        expect(ctx.state.cursor(plan.key)).toEqual({ slot: 1_000, caughtUp: true });
    });

    it('resumes a budget-limited gap-fill at the start of the slot it stopped in', async () => {
        const ctx = context();
        ctx.state.advanceCursor(plan.key, 500, true);
        const requests: ScanRequest[] = [];
        const partial = {
            results: [],
            progress: { windowEnded: false, scannedTransactions: 1_000, scannedThrough: { slot: 700, blockTime: null } },
        };
        const [result] = await backfill(config, fakeEvents(partial, requests), new Engine(ctx, []), ctx.state, [plan], 1_000, {
            alertMode: 'send',
        });
        expect(requests[0]!.sortOrder).toBe('asc');
        expect(result!.coverage).toBe('behind');
        expect(caughtUp(result!)).toBe(false);
        expect(ctx.state.cursor(plan.key)).toEqual({ slot: 699, caughtUp: true });
    });

    it('processes a newest-first scan oldest-first, so proposals precede their approvals', async () => {
        const ctx = context();
        const seen: string[] = [];
        const engine = new Engine(ctx, []);
        const original = engine.process.bind(engine);
        engine.process = (tx, mode) => {
            seen.push(tx.signature);
            return original(tx, mode);
        };
        const page = { results: [upgradeResult('newer', 900), upgradeResult('older', 800)], progress: { windowEnded: true } };
        await backfill(config, fakeEvents(page), engine, ctx.state, [plan], 1_000, { alertMode: 'send' });
        expect(seen).toEqual(['older', 'newer']);
    });

    it("starts an admin key's profile where its first scan's coverage begins", async () => {
        const keyPlan: ScanPlan = {
            ...plan,
            key: `adminkey:${KEYS.program}:${KEYS.member}`,
            address: KEYS.member,
            detectors: ['admin-key-behavior'],
        };
        const lastSeen = (ctx: ReturnType<typeof context>) =>
            ctx.state.recordAdminKeyUse(`${KEYS.program}:${KEYS.member}`, { instructions: [], parties: [], programs: [] }, 0)?.lastSeen;

        const full = context();
        const page = { results: [], progress: { windowEnded: true } };
        await backfill(config, fakeEvents(page), new Engine(full, []), full.state, [keyPlan], 1_000, { alertMode: 'send' });
        expect(lastSeen(full)).toBeCloseTo(Date.now() / 1000 - 30 * 86_400, -2);

        const partial = context();
        const cut = { results: [], progress: { windowEnded: false, scannedThrough: { slot: 900, blockTime: 1_790_000_000 } } };
        await backfill(config, fakeEvents(cut), new Engine(partial, []), partial.state, [keyPlan], 1_000, { alertMode: 'send' });
        expect(lastSeen(partial)).toBe(1_790_000_000);
    });

    it('reports a failed plan and keeps scanning the rest', async () => {
        const ctx = context();
        const other: ScanPlan = { ...plan, key: 'multisig:x', detectors: ['multisig-change'], subject: KEYS.multisig };
        let calls = 0;
        const events = {
            async *scanAll(_request: ScanRequest, _budget: number, onProgress?: (p: ScanProgress) => void) {
                if (calls++ === 0) throw new Error('HTTP 400');
                onProgress?.({ windowEnded: true, scannedTransactions: 10, matchedTransactions: 0, creditsCharged: 11 });
                yield* [];
            },
        } as unknown as ParsedEventsClient;
        const results = await backfill(config, events, new Engine(ctx, []), ctx.state, [plan, other], 1_000, { alertMode: 'send' });
        expect(results.map((r) => r.error ?? 'ok')).toEqual(['HTTP 400', 'ok']);
        expect(ctx.state.cursor(plan.key)).toBeUndefined();
        expect(ctx.state.cursor(other.key)?.caughtUp).toBe(true);
    });
});

describe('targets', () => {
    it('splits large instruction lists to fit Parsed Streams and Parsed Events limits', () => {
        const privilegedInstructions = Array.from({ length: 120 }, (_, i) => `admin_${i}`);
        const cfg = { programs: [{ id: KEYS.program, privilegedInstructions }], multisigs: [], mints: [] } as unknown as Config;
        const { targets } = context();
        const adminSubs = subscriptions(cfg, targets).filter((s) => s.label.startsWith('admin:'));
        expect(adminSubs.map((s) => s.filter.instructionNames!.length)).toEqual([50, 50, 20]);
        const adminPlans = scanPlans(cfg, targets).filter((p) => p.detectors.includes('privileged-instruction'));
        expect(adminPlans.map((p) => p.match.programs![0]!.instructions!.length)).toEqual([50, 50, 20]);
        expect(adminPlans.every((p) => p.status === 'any')).toBe(true);
    });

    it('refuses a config that needs more than 25 subscriptions', () => {
        const programs = Array.from({ length: 30 }, () => ({ id: KEYS.program, privilegedInstructions: ['admin'] }));
        const cfg = { programs, multisigs: [], mints: [] } as unknown as Config;
        expect(() => subscriptions(cfg, context().targets)).toThrow(/allows 25/);
    });
});

describe('state', () => {
    it('does not set a signer baseline from an instruction with no signers', () => {
        const { state } = context();
        expect(state.recordSigners('k', [])).toEqual([]);
        expect(state.recordSigners('k', ['a'])).toEqual([]);
        expect(state.recordSigners('k', ['a', 'b'])).toEqual(['b']);
    });

    it('rejects a state file from an older version with a clear message', () => {
        const path = join(mkdtempSync(join(tmpdir(), 'watchtower-state-')), 'state.json');
        writeFileSync(path, JSON.stringify({ version: 1, cursors: {} }));
        expect(() => new StateStore(path)).toThrow(/older Watchtower version/);
    });
});
