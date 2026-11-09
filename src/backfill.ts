import type { Config } from './config.js';
import { startAdminKeyProfile } from './detectors/adminKeyBehavior.js';
import type { AlertMode, Engine } from './engine.js';
import type { ParsedEventsClient, ScanProgress, ScanRequest } from './helius/parsedEvents.js';
import { fromParsedEvents, type ParsedTx } from './model.js';
import type { StateStore } from './state.js';
import type { ScanPlan } from './targets.js';

/**
 * - `complete`: the whole requested window was scanned.
 * - `recent-only`: a first scan that stopped at the budget. Older history in the lookback window is never scanned.
 * - `behind`: a gap-fill that stopped at the budget; the next run resumes where it stopped.
 */
export type Coverage = 'complete' | 'recent-only' | 'behind' | 'failed';

export interface BackfillResult {
    plan: ScanPlan;
    progress: ScanProgress;
    coverage: Coverage;
    /** What `coverage` means for this scan, for the dashboard and reports. */
    summary: { label: string; detail: string };
    findings: number;
    error?: string;
}

/** Whether the plan's cursor reached the requested slot, so the stream may advance it from there. */
export const caughtUp = (result: BackfillResult): boolean => result.coverage === 'complete' || result.coverage === 'recent-only';

function summarize(coverage: Coverage, progress: ScanProgress, lookbackDays: number, error?: string): BackfillResult['summary'] {
    const blockTime = progress.scannedThrough?.blockTime;
    const when = blockTime ? `${new Date(blockTime * 1000).toISOString().replace('T', ' ').slice(0, 16)} UTC` : null;
    switch (coverage) {
        case 'complete':
            return { label: 'Up to date', detail: 'Every transaction in the window was scanned.' };
        case 'recent-only':
            return {
                label: 'Recent only',
                detail: `The scan budget covered the newest ${progress.scannedTransactions.toLocaleString('en-US')} transactions${when ? `, back to ${when}` : ''}; older history in the ${lookbackDays}-day lookback was not searched. Live alerts cover everything from now on.`,
            };
        case 'behind':
            return {
                label: 'Behind',
                detail: `The scan budget ran out${when ? ` at ${when}` : ''}; the next reconnect or restart continues from there.`,
            };
        case 'failed':
            return { label: 'Failed', detail: error ?? 'The scan failed.' };
    }
}

export interface BackfillOptions {
    /** For caught-up subjects only; findings about subjects still on their first scan are silent. */
    alertMode: Exclude<AlertMode, 'silent'>;
    onProgress?: (plan: ScanPlan, progress: ScanProgress) => void;
}

/**
 * Gap-fills scan oldest-first from the cursor. A first scan reads the lookback window newest-first so the
 * budget covers recent history, processes it oldest-first, and then counts as caught up.
 */
export async function backfill(
    config: Config,
    events: ParsedEventsClient,
    engine: Engine,
    state: StateStore,
    plans: ScanPlan[],
    untilSlot: number,
    options: BackfillOptions,
): Promise<BackfillResult[]> {
    const results: BackfillResult[] = [];
    const finish = (plan: ScanPlan, progress: ScanProgress, coverage: Coverage, findings: number, error?: string) =>
        results.push({
            plan,
            progress,
            coverage,
            summary: summarize(coverage, progress, config.backfill.lookbackDays, error),
            findings,
            error,
        });
    for (const plan of plans) {
        let progress: ScanProgress = { windowEnded: false, scannedTransactions: 0, matchedTransactions: 0, creditsCharged: 0 };
        let findings = 0;
        const firstScan = state.cursor(plan.key) === undefined;
        // A plan's first scan reads history from before monitoring began, so only later scans alert.
        const mode: AlertMode = firstScan ? 'silent' : options.alertMode;
        const alertMode = () => mode;
        if (firstScan && plan.skipFirstScan) {
            state.advanceCursor(plan.key, untilSlot, true);
            finish(plan, { ...progress, windowEnded: true }, 'complete', 0);
            continue;
        }
        try {
            const scan = events.scanAll(scanRequest(config, plan, state, untilSlot), config.backfill.maxScannedTransactions, (latest) => {
                progress = { ...latest };
                options.onProgress?.(plan, latest);
            });
            const newestFirst: ParsedTx[] = [];
            for await (const result of scan) {
                const tx = fromParsedEvents(result);
                if (!tx) continue;
                if (firstScan) newestFirst.push(tx);
                else findings += (await engine.process(tx, alertMode)).length;
            }
            if (firstScan) {
                // A budget-limited first scan covers only back to where it stopped.
                const since = progress.windowEnded ? lookbackStart(config) : progress.scannedThrough?.blockTime;
                if (since) startAdminKeyProfile(state, plan, since);
            }
            for (const tx of newestFirst.reverse()) findings += (await engine.process(tx, alertMode)).length;
        } catch (error) {
            finish(plan, progress, 'failed', findings, (error as Error).message);
            state.save();
            continue;
        }

        if (firstScan || progress.windowEnded) {
            state.advanceCursor(plan.key, untilSlot, true);
        } else if (progress.scannedThrough) {
            // The budget can stop mid-slot; resume at the start of that slot.
            state.advanceCursor(plan.key, progress.scannedThrough.slot - 1, false);
        }
        state.save();
        finish(plan, progress, progress.windowEnded ? 'complete' : firstScan ? 'recent-only' : 'behind', findings);
    }
    return results;
}

/** Unix seconds where a first scan's lookback window starts. */
function lookbackStart(config: Config): number {
    return Math.floor(Date.now() / 1000) - config.backfill.lookbackDays * 86_400;
}

function scanRequest(config: Config, plan: ScanPlan, state: StateStore, untilSlot: number) {
    const cursor = state.cursor(plan.key);
    const sortOrder = cursor ? 'asc' : 'desc';
    const window = cursor
        ? { slot: { gt: cursor.slot, lte: untilSlot } }
        : {
              time: { gte: lookbackStart(config) },
              slot: { lte: untilSlot },
          };
    return {
        address: plan.address,
        match: plan.match,
        status: plan.status,
        sortOrder,
        limit: 100,
        minContextSlot: untilSlot,
        ...window,
    } satisfies Omit<ScanRequest, 'paginationToken' | 'budget'>;
}
