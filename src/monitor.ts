import { EventEmitter } from 'node:events';
import { backfill, caughtUp, type BackfillResult } from './backfill.js';
import { severityRank, type Config } from './config.js';
import { checkConfigChanges } from './configWatch.js';
import type { Finding } from './detectors/types.js';
import { PROGRAMS } from './constants.js';
import { checkBuild } from './discover/build.js';
import { short } from './format.js';
import { ParsedStreamsClient, type StreamFilter, type Subscription } from './helius/parsedStreams.js';
import { checkIdlChanges } from './idlWatch.js';
import { fromStream } from './model.js';
import { createRuntime, refreshDiscovery, type Runtime } from './runtime.js';
import { subscriptions } from './targets.js';

/** Held back from the ping slot when advancing cursors; covers transactions still in the parse pipeline. */
const CURSOR_SAFETY_SLOTS = 150;
const HEARTBEAT_MS = 5 * 60_000;
/** Coalesces state saves during a burst of findings. */
const SAVE_DELAY_MS = 1_000;
/** Let a burst of admin calls or authority changes settle before reading accounts or rediscovering. */
const CONFIG_CHECK_DELAY_MS = 2_000;
const REDISCOVER_DELAY_MS = 10_000;
/** An upgrade still unverified after this long alerts. */
const BUILD_RECHECK_MS = 30 * 60_000;

export type MonitorPhase = 'starting' | 'catching-up' | 'live' | 'reconnecting' | 'stopped' | 'error';
export type LogLevel = 'info' | 'success' | 'warn' | 'error' | 'detail';

export interface MonitorStatus {
    phase: MonitorPhase;
    error: string | null;
    connectedSince: number | null;
    serverSlot: number;
    /** Notifications per subscription since the monitor started. */
    received: Record<string, number>;
    subscriptions: Subscription[];
    coverage: BackfillResult[];
}

export interface MonitorEvents {
    log: [level: LogLevel, message: string];
    finding: [finding: Finding];
    status: [status: MonitorStatus];
    /** Discovery ran again after an authority change. */
    targets: [];
}

/** Gap-fills with Parsed Events on each connection, then streams with Parsed Streams. */
export class Monitor extends EventEmitter<MonitorEvents> {
    readonly config: Config;
    readonly #backfill: boolean;
    #runtime: Runtime | undefined;
    #client: ParsedStreamsClient | undefined;
    #timers: NodeJS.Timeout[] = [];
    #queue: Promise<unknown> = Promise.resolve();
    #saveTimer: NodeJS.Timeout | undefined;
    #timeouts = new Map<string, NodeJS.Timeout>();
    #caughtUp = new Set<string>();
    #pending = 0;
    /** Highest notification slot received; everything up to it is in the queue or processed. */
    #streamSlot = 0;
    #stopped = false;
    /** Set once the first catch-up finishes; before that, startup discovery already reflects what findings imply. */
    #followUps = false;
    #catchUp: Promise<void> | undefined;
    #sinceHeartbeat = new Map<string, number>();
    #status: MonitorStatus = {
        phase: 'starting',
        error: null,
        connectedSince: null,
        serverSlot: 0,
        received: {},
        subscriptions: [],
        coverage: [],
    };

    constructor(config: Config, options: { backfill: boolean }) {
        super();
        this.config = config;
        this.#backfill = options.backfill;
    }

    get runtime(): Runtime | undefined {
        return this.#runtime;
    }

    status(): MonitorStatus {
        return this.#status;
    }

    async start(): Promise<void> {
        try {
            await this.#start();
        } catch (error) {
            this.#setStatus({ phase: 'error', error: (error as Error).message });
            this.emit('log', 'error', (error as Error).message);
            throw error;
        }
    }

    async stop(): Promise<void> {
        this.#stopped = true;
        for (const timer of this.#timers) clearInterval(timer);
        for (const timer of this.#timeouts.values()) clearTimeout(timer);
        clearTimeout(this.#saveTimer);
        this.#client?.stop();
        await this.#catchUp?.catch(() => undefined);
        await this.#queue;
        await this.#runtime?.engine.close();
        this.#runtime?.state.save();
        this.#setStatus({ phase: 'stopped', connectedSince: null });
    }

    async #start(): Promise<void> {
        this.emit('log', 'info', 'Discovering targets…');
        const runtime = await createRuntime(this.config, { onRecord: (finding) => this.#onFinding(finding) });
        this.#runtime = runtime;
        if (this.#stopped) return;
        const subs = subscriptions(this.config, runtime.ctx.targets);
        this.#describeTargets(subs);

        const flushed = await runtime.engine.flushPendingAlerts();
        if (flushed > 0) this.emit('log', 'info', `Delivered ${flushed} queued alert(s)`);
        runtime.state.save();

        await this.#pollIdls();
        await this.#checkConfigs();
        if (this.#stopped) return;
        this.#timers.push(setInterval(() => void this.#pollIdls(), this.config.idlPollMinutes * 60_000));
        this.#timers.push(setInterval(() => void this.#checkConfigs(), this.config.configPollSeconds * 1000));
        this.#timers.push(
            setInterval(() => {
                const counts = [...this.#sinceHeartbeat].map(([label, n]) => `${label} ${n}`).join(', ') || 'none';
                this.emit(
                    'log',
                    'detail',
                    `Heartbeat: notifications in the last ${HEARTBEAT_MS / 60_000} min: ${counts}; server slot ${this.#status.serverSlot.toLocaleString('en-US')}`,
                );
                this.#sinceHeartbeat = new Map();
            }, HEARTBEAT_MS),
        );
        this.#connect(subs);
    }

    #describeTargets(subs: Subscription[]): void {
        const { targets } = this.#runtime!.ctx;
        this.#setStatus({ subscriptions: subs });
        this.emit(
            'log',
            'info',
            `Watching ${targets.programs.size} program(s), ${targets.multisigs.size} multisig(s), ${targets.mints.size} mint(s), ${targets.treasuries.size} treasury(ies)`,
        );
        const names = new Map<string, string>([...KNOWN_PROGRAMS, ...[...targets.programs.values()].map((p) => [p.id, p.label] as const)]);
        for (const sub of subs) this.emit('log', 'detail', `Stream ${streamLabel(sub.label, names)}: ${describeFilter(sub.filter, names)}`);
        for (const program of this.#runtime!.discovery.programs) {
            const label = names.get(program.programId) ?? program.programId;
            if (program.unlocatedConfigs.length > 0) {
                this.emit(
                    'log',
                    'warn',
                    `${label}: could not locate its ${program.unlocatedConfigs.join(', ')} account(s), so admin keys stored there are not watched`,
                );
            }
            const privileged = this.config.programs.find((p) => p.id === program.programId)?.privilegedInstructions ?? [];
            if (privileged.length > 0 && program.admins.length === 0) {
                this.emit(
                    'log',
                    'warn',
                    `${label}: no admin key found, so no admin's own history is scanned. Admin calls are still caught live by instruction name, and their signers are watched once seen`,
                );
            }
        }
    }

    #connect(subs: Subscription[]): void {
        const runtime = this.#runtime!;
        let connection = 0;
        this.#client = new ParsedStreamsClient(this.config.endpoints.parsedStreams, this.config.apiKey, subs, {
            onTransaction: (value, label) => {
                this.#sinceHeartbeat.set(label, (this.#sinceHeartbeat.get(label) ?? 0) + 1);
                this.#status.received[label] = (this.#status.received[label] ?? 0) + 1;
                this.#pending++;
                this.#queue = this.#queue
                    .then(() => runtime.engine.process(fromStream(value), () => 'send'))
                    .then((findings) => findings.length > 0 && this.#saveSoon())
                    .catch((error: Error) => {
                        this.#caughtUp = new Set();
                        this.emit(
                            'log',
                            'error',
                            `Failed to process ${value.transaction.signature}: ${error.message}. It will be retried by the next gap-fill.`,
                        );
                    })
                    .finally(() => {
                        this.#pending--;
                        this.#advanceCursors();
                    });
            },
            onConnected: ({ reconnect, rejected }) => {
                this.#catchUp = this.#onConnected(++connection, () => connection, reconnect, rejected);
                return this.#catchUp;
            },
            onDisconnected: ({ code, reason }) => {
                this.#caughtUp = new Set();
                this.#setStatus({ phase: 'reconnecting', connectedSince: null });
                this.emit('log', 'warn', `Parsed Streams disconnected (${code}${reason ? ` ${reason}` : ''}); reconnecting`);
            },
            onSlot: (slot) => {
                this.#streamSlot = Math.max(this.#streamSlot, slot);
                this.#setStatus({ serverSlot: slot });
            },
            onError: (error) => this.emit('log', 'error', error.message),
        });
        this.#client.start();
    }

    /** Gap-fills up to the present, then lets the stream advance the cursors of the plans that completed. */
    async #onConnected(connection: number, latest: () => number, reconnect: boolean, rejected: string[]): Promise<void> {
        const runtime = this.#runtime!;
        this.#caughtUp = new Set();
        this.emit('log', 'success', reconnect ? 'Reconnected to Parsed Streams' : 'Connected to Parsed Streams');
        if (rejected.length > 0) {
            this.emit(
                'log',
                'warn',
                `Cursors only move on reconnect while ${rejected.join(', ')} is rejected, so each gap-fill rescans from the last connect`,
            );
        }
        if (!this.#backfill) {
            this.#followUps = true;
            this.#setStatus({ phase: 'live', connectedSince: Date.now() });
            return;
        }
        this.#setStatus({ phase: 'catching-up', connectedSince: Date.now() });
        try {
            const untilSlot = await runtime.rpc.getSlot();
            if (this.#stopped || connection !== latest()) return;
            this.emit('log', 'info', `Backfilling up to slot ${untilSlot.toLocaleString('en-US')} with Parsed Events…`);
            const results = await backfill(this.config, runtime.events, runtime.engine, runtime.state, runtime.plans, untilSlot, {
                alertMode: 'send',
            });
            for (const r of results) {
                const { label, detail } = r.summary;
                this.emit(
                    'log',
                    r.coverage === 'failed' ? 'error' : r.coverage === 'complete' ? 'detail' : 'warn',
                    `${r.plan.label}: ${r.progress.scannedTransactions} scanned, ${r.findings} new finding(s). ${label}: ${detail}`,
                );
            }
            if (this.#stopped || connection !== latest()) return;
            if (rejected.length === 0) this.#caughtUp = new Set(results.filter(caughtUp).map((r) => r.plan.key));
            this.#followUps = true;
            this.#setStatus({ phase: 'live', coverage: results });
        } catch (error) {
            this.emit('log', 'error', `Gap-fill failed: ${(error as Error).message}. It runs again on the next reconnect.`);
            this.#setStatus({ phase: 'live' });
        }
    }

    /** Moves caught-up cursors to the latest notification slot once every notification before it is processed. */
    #advanceCursors(): void {
        if (this.#caughtUp.size === 0 || this.#pending > 0 || this.#streamSlot === 0) return;
        for (const key of this.#caughtUp) this.#runtime!.state.advanceCursor(key, this.#streamSlot - CURSOR_SAFETY_SLOTS, true);
        this.#saveSoon();
    }

    /** Follow-up work runs only after the first catch-up: startup discovery already reflects what earlier findings imply. */
    #onFinding(finding: Finding): void {
        this.emit('finding', finding);
        if (!this.#followUps || this.#stopped) return;
        if (finding.detector === 'privileged-instruction') this.#later('config-check', CONFIG_CHECK_DELAY_MS, () => this.#checkConfigs());
        if (changesAuthority(finding)) this.#later('rediscover', REDISCOVER_DELAY_MS, () => this.#rediscover(finding.title));
        if (finding.detector === 'program-deployment' && finding.details['Verified build']?.startsWith('No')) {
            this.#later(`build:${finding.id}`, BUILD_RECHECK_MS, () => this.#recheckBuild(finding));
        }
    }

    /** Runs `task` once after `delayMs`; further calls with the same key before then are merged into it. */
    #later(key: string, delayMs: number, task: () => Promise<void>): void {
        if (this.#timeouts.has(key)) return;
        this.#timeouts.set(
            key,
            setTimeout(() => {
                this.#timeouts.delete(key);
                void task();
            }, delayMs),
        );
    }

    /** Resubscribes only if the rediscovered targets change the stream filters. */
    async #rediscover(reason: string): Promise<void> {
        const runtime = this.#runtime!;
        this.emit('log', 'warn', `Control changed (${reason}); discovering authorities again…`);
        try {
            await refreshDiscovery(runtime);
        } catch (error) {
            this.emit('log', 'error', `Failed to discover authorities again: ${(error as Error).message}. Restart to retry.`);
            return;
        }
        if (this.#stopped) return;
        const subs = subscriptions(this.config, runtime.ctx.targets);
        const changed = JSON.stringify(subs) !== JSON.stringify(this.#status.subscriptions);
        this.#describeTargets(subs);
        this.emit('targets');
        if (!changed) return;
        this.emit('log', 'info', 'Stream filters changed; reconnecting to Parsed Streams with the new targets');
        this.#client?.stop();
        this.#connect(subs);
    }

    async #recheckBuild(finding: Finding): Promise<void> {
        const runtime = this.#runtime!;
        const program = runtime.ctx.targets.programs.get(finding.subject);
        if (!program?.programData) return;
        try {
            const build = await checkBuild(runtime.rpc, program.id, program.programData);
            if (build.deploySlot !== finding.slot) return;
            if (build.verified) {
                this.emit('log', 'success', `The upgrade of ${program.label} now matches its verified build (${build.source}).`);
                return;
            }
            await runtime.engine.record(
                {
                    ...finding,
                    id: `build-verification:${finding.signature}`,
                    detector: 'build-verification',
                    severity: build.source ? 'critical' : 'high',
                    title: 'Upgrade still not a verified build',
                    description: `${BUILD_RECHECK_MS / 60_000} minutes after the upgrade, ${program.label}'s bytecode (hash ${build.hash.slice(0, 12)}…) still does not match ${build.source ? `its registered source ${build.source}` : 'any verified build'}.`,
                    details: { ...finding.details, 'Bytecode hash': build.hash },
                    stages: ['control'],
                },
                'send',
            );
            this.#saveSoon();
        } catch (error) {
            this.emit('log', 'error', `Failed to re-check the build of ${program.label}: ${(error as Error).message}`);
        }
    }

    #saveSoon(): void {
        this.#saveTimer ??= setTimeout(() => {
            this.#saveTimer = undefined;
            this.#runtime?.state.save();
        }, SAVE_DELAY_MS);
    }

    async #checkConfigs(): Promise<void> {
        try {
            const found = await checkConfigChanges(this.#runtime!, 'send');
            if (found > 0) this.emit('log', 'warn', `${found} config account change(s) found`);
        } catch (error) {
            this.emit('log', 'error', `Failed to check config accounts: ${(error as Error).message}`);
        }
    }

    async #pollIdls(): Promise<void> {
        const runtime = this.#runtime!;
        try {
            const found = await checkIdlChanges(runtime.events, runtime.engine, runtime.state, runtime.ctx.targets, 'send');
            if (found > 0) this.emit('log', 'info', `${found} IDL change(s) found`);
        } catch (error) {
            this.emit('log', 'error', `Failed to check IDL versions: ${(error as Error).message}`);
        }
    }

    #setStatus(patch: Partial<MonitorStatus>): void {
        this.#status = { ...this.#status, ...patch };
        this.emit('status', this.#status);
    }
}

const KNOWN_PROGRAMS = new Map<string, string>([
    [PROGRAMS.bpfLoaderUpgradeable, 'BPF loader'],
    [PROGRAMS.squadsV4, 'Squads v4'],
    [PROGRAMS.squadsV3, 'Squads v3'],
    [PROGRAMS.splToken, 'SPL Token'],
    [PROGRAMS.token2022, 'Token-2022'],
    [PROGRAMS.system, 'System'],
    [PROGRAMS.stake, 'Stake'],
]);

function streamLabel(label: string, names: Map<string, string>): string {
    const [kind, programId] = label.split(':');
    return programId ? `${kind} (${names.get(programId) ?? short(programId)})` : label;
}

function describeFilter(filter: StreamFilter, names: Map<string, string>): string {
    const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
    return [
        filter.programs?.map((p) => names.get(p) ?? short(p)).join(' + '),
        filter.instructionNames && plural(filter.instructionNames.length, 'instruction'),
        filter.accounts?.include && plural(filter.accounts.include.length, 'account'),
        filter.includeFailed && 'including failed',
    ]
        .filter(Boolean)
        .join(', ');
}

/** Findings after which the watched authorities, multisigs or admin keys may differ from what discovery saw. */
export function changesAuthority(finding: Finding): boolean {
    switch (finding.detector) {
        case 'program-deployment':
            return /authority|immutable|closed|migrated/i.test(finding.title);
        case 'config-change':
            return finding.title.startsWith('Admin changed');
        case 'multisig-change':
            return (
                severityRank(finding.severity) >= severityRank('high') &&
                /member|threshold|authority|time lock|config change executed/i.test(finding.title)
            );
        case 'privileged-instruction':
            return finding.title.includes('Admin control changed');
        case 'key-authority':
            return finding.title.startsWith('Token ');
        default:
            return false;
    }
}
