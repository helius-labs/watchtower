import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Config } from '../src/config.js';
import type { Finding } from '../src/detectors/types.js';
import type { Subscription } from '../src/helius/parsedStreams.js';
import type { Runtime } from '../src/runtime.js';
import { context, KEYS } from './helpers.js';

interface FakeClient {
    subs: Subscription[];
    handlers: {
        onConnected: (info: { reconnect: boolean; rejected: string[] }) => Promise<void>;
        onTransaction: (value: unknown, label: string) => void;
        onSlot: (slot: number) => void;
    };
    stopped: boolean;
}
const clients: FakeClient[] = [];
let onRecord: ((finding: Finding) => void) | undefined;
const refreshDiscovery = vi.fn(async (runtime: Runtime) => {
    runtime.ctx.targets.multisigs.set(KEYS.configTx, {
        address: KEYS.configTx,
        label: 'New admin multisig',
        version: 4,
        threshold: 2,
        timeLockSeconds: 0,
    });
});

vi.mock('../src/helius/parsedStreams.js', () => ({
    ParsedStreamsClient: class {
        stopped = false;
        constructor(
            _url: string,
            _key: string,
            public subs: Subscription[],
            public handlers: FakeClient['handlers'],
        ) {
            clients.push(this as unknown as FakeClient);
        }
        start() {}
        stop() {
            this.stopped = true;
        }
    },
}));
vi.mock('../src/runtime.js', () => ({
    createRuntime: async (_config: Config, options: { onRecord?: (f: Finding) => void }) => {
        onRecord = options.onRecord;
        const ctx = context();
        return {
            ctx,
            state: ctx.state,
            engine: { flushPendingAlerts: async () => 0, close: async () => undefined, process: async () => [] },
            rpc: { getSlot: async () => 1_000 },
            discovery: { programs: [] },
            plans: [],
        };
    },
    refreshDiscovery,
}));
vi.mock('../src/backfill.js', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../src/backfill.js')>()),
    backfill: async () => [
        {
            plan: { key: 'plan', label: 'Plan' },
            coverage: 'complete',
            summary: { label: 'Up to date', detail: '' },
            findings: 0,
            progress: { scannedTransactions: 0 },
        },
    ],
}));
vi.mock('../src/idlWatch.js', () => ({ checkIdlChanges: async () => 0 }));
vi.mock('../src/configWatch.js', () => ({ checkConfigChanges: async () => 0 }));

const { Monitor, changesAuthority } = await import('../src/monitor.js');

const config = {
    idlPollMinutes: 10,
    configPollSeconds: 60,
    programs: [],
    endpoints: { parsedStreams: 'wss://x' },
    apiKey: 'k',
} as unknown as Config;
const finding = (detector: string, title: string, severity: Finding['severity'] = 'critical'): Finding => ({
    id: `${detector}:x`,
    detector,
    severity,
    title,
    description: '',
    subject: KEYS.program,
    subjectLabel: 'Drift',
    signature: null,
    slot: 1,
    blockTime: null,
    details: {},
});

afterEach(() => vi.useRealTimers());

describe('following authority changes', () => {
    it('recognizes findings that change who controls a program', () => {
        expect(changesAuthority(finding('config-change', 'Admin changed in State.admin'))).toBe(true);
        expect(changesAuthority(finding('program-deployment', 'Upgrade authority changed'))).toBe(true);
        expect(changesAuthority(finding('privileged-instruction', 'Admin control changed: update_admin', 'high'))).toBe(true);
        expect(changesAuthority(finding('multisig-change', 'Member added', 'high'))).toBe(true);
        expect(changesAuthority(finding('key-authority', 'Token delegate approved', 'high'))).toBe(true);
        expect(changesAuthority(finding('key-authority', 'Stake lockup changed', 'high'))).toBe(false);
        expect(changesAuthority(finding('program-deployment', 'Program upgraded', 'high'))).toBe(false);
        expect(changesAuthority(finding('multisig-change', 'Proposal approved', 'info'))).toBe(false);
    });

    it('rediscovers once after a live admin change and resubscribes with the new targets', async () => {
        vi.useFakeTimers();
        const monitor = new Monitor(config, { backfill: false });
        await monitor.start();
        await clients[0]!.handlers.onConnected({ reconnect: false, rejected: [] });
        expect(monitor.status().phase).toBe('live');

        onRecord!(finding('config-change', 'Admin changed in State.admin'));
        onRecord!(finding('privileged-instruction', 'Admin control changed: update_admin', 'high'));
        await vi.advanceTimersByTimeAsync(10_000);

        expect(refreshDiscovery).toHaveBeenCalledTimes(1);
        expect(clients).toHaveLength(2);
        expect(clients[0]!.stopped).toBe(true);
        expect(clients[1]!.subs.find((s) => s.label === 'multisigs')?.filter.accounts?.include).toContain(KEYS.configTx);
        await monitor.stop();
    });

    it('ignores authority changes found while catching up, since startup discovery already saw them', async () => {
        vi.useFakeTimers();
        refreshDiscovery.mockClear();
        const monitor = new Monitor(config, { backfill: false });
        await monitor.start();
        onRecord!(finding('config-change', 'Admin changed in State.admin'));
        await vi.advanceTimersByTimeAsync(10_000);
        expect(refreshDiscovery).not.toHaveBeenCalled();
        await monitor.stop();
    });
});

describe('cursors', () => {
    const notification = { transaction: { signature: 's', slot: 5_000 }, instructions: [] };

    it('moves caught-up cursors to the latest notification slot once the queue drains', async () => {
        const monitor = new Monitor(config, { backfill: true });
        await monitor.start();
        const { handlers } = clients.at(-1)!;
        await handlers.onConnected({ reconnect: false, rejected: [] });
        expect(monitor.runtime!.state.cursor('plan')).toBeUndefined();

        handlers.onTransaction(notification, 'admin');
        handlers.onSlot(5_000);
        await vi.waitFor(() => expect(monitor.runtime!.state.cursor('plan')).toEqual({ slot: 4_850, caughtUp: true }));
        await monitor.stop();
    });

    it('leaves cursors alone while a subscription is rejected, since its slots were never streamed', async () => {
        const monitor = new Monitor(config, { backfill: true });
        await monitor.start();
        const { handlers } = clients.at(-1)!;
        await handlers.onConnected({ reconnect: false, rejected: ['admin'] });
        handlers.onTransaction(notification, 'mints');
        handlers.onSlot(5_000);
        await new Promise((resolve) => setTimeout(resolve, 10));
        expect(monitor.runtime!.state.cursor('plan')).toBeUndefined();
        await monitor.stop();
    });
});
