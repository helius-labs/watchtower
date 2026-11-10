import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import {
    endpointsFromEnv,
    loadConfig,
    loadEnvFile,
    parseConfig,
    requireApiKey,
    severityRank,
    type Config,
    type Severity,
} from '../config.js';
import { CONFIG_CHANGE_ID } from '../configWatch.js';
import { startAdminKeyProfile } from '../detectors/adminKeyBehavior.js';
import { ATTACK_CHAIN_ID } from '../detectors/attackChain.js';
import { DETECTOR_IDS } from '../detectors/index.js';
import type { Finding, WatchTargets } from '../detectors/types.js';
import { fetchIdl } from '../discover/index.js';
import { ParsedEventsClient, type ScanRequest } from '../helius/parsedEvents.js';
import { RpcClient } from '../helius/rpc.js';
import { heliusClient } from '../helius/sdk.js';
import { idlChangesBetween, IDL_CHANGE_ID } from '../idlWatch.js';
import { fromParsedEvents, type ParsedTx } from '../model.js';
import { createRuntime } from '../runtime.js';
import { poweredByHelius } from '../style.js';
import type { ScanPlan } from '../targets.js';

export interface ReplayOptions {
    config: string;
    program?: string[];
    from: string;
    to: string;
    budget: string;
    minSeverity: Severity;
    json?: string;
    programScans: boolean;
}

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
    critical: (t) => pc.bold(pc.red(t)),
    high: pc.red,
    medium: pc.yellow,
    low: pc.dim,
    info: pc.dim,
};

/** Transactions from all scan plans are merged and processed in slot order, so findings link across plans as they would live. */
export async function replayCommand(options: ReplayOptions): Promise<void> {
    const window: Pick<ScanRequest, 'slot' | 'time'> = {};
    for (const [flag, value, op] of [
        ['from', options.from, 'gte'],
        ['to', options.to, 'lte'],
    ] as const) {
        const [key, range] = bound(flag, value, op);
        window[key] = { ...window[key], ...range };
    }
    const budget = Number(options.budget);
    if (!Number.isInteger(budget) || budget <= 0) throw new Error('--budget must be a positive whole number');

    loadEnvFile();
    const apiKey = requireApiKey();
    const endpoints = endpointsFromEnv();
    const helius = heliusClient(apiKey, endpoints);
    const idlAtSlot = await slotAt(new RpcClient(helius), window.slot?.gte, window.time?.gte);
    const events = new ParsedEventsClient(helius, apiKey);
    const config = options.program?.length
        ? await adHocConfig(options.program, events, idlAtSlot, apiKey, endpoints)
        : loadConfig(options.config);
    config.stateFile = join(mkdtempSync(join(tmpdir(), 'watchtower-replay-')), 'state.json');
    config.alerts = { minSeverity: 'critical', sinks: [], groupWindowSeconds: 0 };

    const spinner = p.spinner();
    spinner.start('Discovering authorities, multisigs and vaults as they are today');
    const runtime = await createRuntime(config, { idlAtSlot });
    const { targets } = runtime.ctx;
    spinner.stop(
        `Watching ${targets.programs.size} program(s), ${targets.multisigs.size} multisig(s), ${targets.treasuries.size} treasury/vault(s)`,
    );

    const transactions = new Map<string, ParsedTx>();
    let credits = 0;
    const scans: PlanScan[] = [];
    for (const plan of runtime.plans) {
        if (!options.programScans && targets.programs.has(plan.address)) {
            scans.push({ plan, outcome: 'skipped' });
            continue;
        }
        spinner.start(`${plan.label}: scanning`);
        let ended = false;
        let scanned = 0;
        let planCredits = 0;
        const scan = runtime.events.scanAll(
            { address: plan.address, match: plan.match, status: plan.status, sortOrder: 'asc', limit: 100, ...window },
            budget,
            (progress) => {
                ended = progress.windowEnded;
                scanned = progress.scannedTransactions;
                planCredits = progress.creditsCharged;
                spinner.message(`${plan.label}: ${scanned.toLocaleString('en-US')} transactions scanned`);
            },
        );
        for await (const result of scan) {
            const tx = fromParsedEvents(result);
            if (tx) transactions.set(tx.signature, tx);
        }
        credits += planCredits;
        scans.push({ plan, outcome: ended ? 'complete' : 'budget' });
        spinner.stop(
            `${plan.label}: ${scanned.toLocaleString('en-US')} scanned${ended ? '' : pc.yellow(' (budget reached, window not finished)')}`,
        );
    }

    // Scans read oldest-first, so even a budget-limited one covers the window from its start.
    const windowStart = window.time?.gte ?? (await runtime.rpc.getBlockTime(idlAtSlot));
    for (const { plan, outcome } of scans) if (outcome !== 'skipped') startAdminKeyProfile(runtime.state, plan, windowStart);

    const ordered = [...transactions.values()].sort((a, b) => a.slot - b.slot);
    const findings: Finding[] = [];
    for (const tx of ordered) findings.push(...(await runtime.engine.process(tx, () => 'silent')));

    spinner.start('Checking IDL versions published in the window');
    const toSlot = await slotAt(runtime.rpc, window.slot?.lte, window.time?.lte);
    const idlChanges = await idlChangesBetween(runtime.events, targets, idlAtSlot, toSlot);
    findings.push(...idlChanges);
    spinner.stop(`IDL versions: ${idlChanges.length} published in the window`);

    const coverage = detectorCoverage(scans, config, targets, idlChanges.length);
    printTimeline(findings, options.minSeverity, ordered.length, coverage);
    printCoverage(coverage);
    console.log(pc.dim(`\nParsed Events credits used by the scans: ${credits.toLocaleString('en-US')}`));
    console.log(`\n${poweredByHelius()}`);

    if (options.json) {
        const path = resolve(options.json);
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, JSON.stringify({ window: { from: options.from, to: options.to }, coverage, findings }, null, 2));
        console.log(`${pc.bold('JSON:')} ${path}`);
    }
}

export type CoverageStatus = 'ran' | 'missing-data' | 'nothing-to-watch' | 'live-only';

export interface DetectorCoverage {
    detector: string;
    status: CoverageStatus;
    reason: string;
}

export interface PlanScan {
    plan: ScanPlan;
    /** `budget`: stopped at `--budget` before the window end. `skipped`: a program-wide plan under `--no-program-scans`. */
    outcome: 'complete' | 'budget' | 'skipped';
}

const BUILD_VERIFICATION_ID = 'build-verification';

/** Detectors that need state no historical API serves. */
const LIVE_ONLY = new Map([
    [
        CONFIG_CHANGE_ID,
        'Compares successive reads of config accounts, and RPC does not serve past account states. Admin instructions that write them are still checked by privileged-instruction.',
    ],
    [
        'nonce-authority',
        'Watches nonce instructions chain-wide, since the privileged key is only an argument and an address scan cannot find them. Replay sees only those in transactions other scans returned.',
    ],
    [
        BUILD_VERIFICATION_ID,
        "Rechecks an upgrade 30 minutes after it lands. Upgrade alerts still say whether the bytecode is a verified build, unless it's been replaced since.",
    ],
]);

const NOTHING_TO_WATCH = new Map([
    ['program-deployment', 'No upgradeable program is watched.'],
    ['upgrade-proposal', 'No Squads multisig is watched.'],
    ['multisig-proposal', 'No Squads multisig is watched.'],
    ['multisig-change', 'No Squads multisig is watched.'],
    ['mint-authority', 'No mint is watched.'],
    [
        'permanent-delegate',
        "No watched mint has a permanent delegate, and no treasury or vault holds a token that has one. Holdings are read from today's token accounts.",
    ],
    ['privileged-instruction', 'No program is watched.'],
    ['admin-key-behavior', "No admin key is known. List them under the program's adminKeys when its IDL doesn't reveal them."],
    [
        'treasury-outflow',
        "No treasury or vault is watched. Vaults are discovered from today's balances, so one emptied since the window is not found.",
    ],
    ['key-authority', 'No treasury or custody key is watched.'],
]);

/** What each detector covered in a replay, so a quiet timeline isn't read as a clean one. */
export function detectorCoverage(scans: PlanScan[], config: Config, targets: WatchTargets, idlChanges: number): DetectorCoverage[] {
    const noAdminInstructions = config.programs
        .filter((p) => p.privilegedInstructions.length === 0)
        .map((p) => targets.programs.get(p.id)?.label ?? p.id);
    const liveOnly = (detector: string): DetectorCoverage => ({ detector, status: 'live-only', reason: LIVE_ONLY.get(detector)! });
    const scanned = DETECTOR_IDS.map((detector) =>
        LIVE_ONLY.has(detector)
            ? liveOnly(detector)
            : fromScans(
                  detector,
                  scans.filter((s) => s.plan.detectors.includes(detector)),
                  detector === 'privileged-instruction' && noAdminInstructions.length > 0
                      ? [`No admin instructions are known for ${noAdminInstructions.join(', ')}, so its calls were not checked.`]
                      : [],
              ),
    );
    const linked = scanned.filter((c) => c.status !== 'live-only' && c.status !== 'nothing-to-watch');
    return [
        ...scanned,
        targets.programs.size === 0
            ? { detector: IDL_CHANGE_ID, status: 'nothing-to-watch', reason: 'No program is watched.' }
            : {
                  detector: IDL_CHANGE_ID,
                  status: 'ran',
                  reason: `Checked the IDL versions of ${targets.programs.size} program(s): ${idlChanges} published in the window.`,
              },
        liveOnly(CONFIG_CHANGE_ID),
        liveOnly(BUILD_VERIFICATION_ID),
        linked.length === 0
            ? { detector: ATTACK_CHAIN_ID, status: 'nothing-to-watch', reason: 'No detector it links had anything to watch.' }
            : linked.every((c) => c.status === 'ran')
              ? { detector: ATTACK_CHAIN_ID, status: 'ran', reason: 'Linked the findings of the detectors above.' }
              : {
                    detector: ATTACK_CHAIN_ID,
                    status: 'missing-data',
                    reason: `Links the findings of the detectors above, and ${linked
                        .filter((c) => c.status !== 'ran')
                        .map((c) => c.detector)
                        .join(', ')} missed data.`,
                },
    ];
}

function fromScans(detector: string, scans: PlanScan[], gaps: string[]): DetectorCoverage {
    const labels = (outcome: PlanScan['outcome']) => [...new Set(scans.filter((s) => s.outcome === outcome).map((s) => s.plan.label))];
    const skipped = labels('skipped');
    const budget = labels('budget');
    const reasons = [
        ...(skipped.length > 0
            ? [`Skipped by --no-program-scans: ${skipped.join(', ')}. Only calls signed by discovered admin keys were checked.`]
            : []),
        ...(budget.length > 0 ? [`Stopped at --budget before the window end: ${budget.join(', ')}.`] : []),
        ...gaps,
    ];
    if (reasons.length > 0) return { detector, status: 'missing-data', reason: reasons.join(' ') };
    if (scans.length === 0) {
        const nothing = NOTHING_TO_WATCH.get(detector);
        return nothing
            ? { detector, status: 'nothing-to-watch', reason: nothing }
            : { detector, status: 'missing-data', reason: 'No scan plan lists it, so it saw only the transactions other scans returned.' };
    }
    return { detector, status: 'ran', reason: `${scans.length} scan(s) covered the whole window.` };
}

/** A window edge as a slot, looked up from block times when the edge is a date. */
async function slotAt(rpc: RpcClient, slot: number | undefined, time: number | undefined): Promise<number> {
    if (slot !== undefined) return slot;
    return time === undefined ? rpc.getSlot() : rpc.slotAtTime(time);
}

/** `--program <id>[:Name]`, with admin instructions from the IDL that was live when the window starts. */
async function adHocConfig(
    programs: string[],
    events: ParsedEventsClient,
    idlAtSlot: number,
    apiKey: string,
    endpoints: Config['endpoints'],
): Promise<Config> {
    const entries = await Promise.all(
        programs.map(async (spec) => {
            const [id = '', name] = spec.split(':');
            const idl = await fetchIdl(events, id, idlAtSlot);
            return { id, ...(name ? { name } : {}), privilegedInstructions: idl?.privileged ?? [] };
        }),
    );
    return { ...parseConfig({ programs: entries }, '--program'), apiKey, endpoints, configPath: '(command line)' };
}

/** `value` is a slot number or anything `Date.parse` reads. */
function bound(flag: string, value: string, op: 'gte' | 'lte'): ['slot' | 'time', { gte?: number; lte?: number }] {
    if (/^\d+$/.test(value)) return ['slot', { [op]: Number(value) }];
    const ms = Date.parse(value);
    if (Number.isNaN(ms)) throw new Error(`--${flag} must be a slot number or a date such as 2026-03-20`);
    return ['time', { [op]: Math.floor(ms / 1000) }];
}

function printTimeline(findings: Finding[], minSeverity: Severity, scanned: number, coverage: DetectorCoverage[]): void {
    const shown = findings.filter((f) => severityRank(f.severity) >= severityRank(minSeverity)).sort((a, b) => a.slot - b.slot);
    console.log(
        `\n${pc.bold('Replay')}  ${findings.length} finding(s) in ${scanned.toLocaleString('en-US')} matching transactions; ${shown.length} at ${minSeverity} or above`,
    );
    const notRun = coverage.filter((c) => c.status !== 'ran').length;
    if (notRun > 0) {
        console.log(
            pc.yellow(
                `${notRun} of ${coverage.length} detectors did not check this whole window, so a quiet timeline does not mean nothing happened. See Detector coverage below.`,
            ),
        );
    }
    console.log();
    for (const f of shown) {
        const when = f.blockTime ? new Date(f.blockTime * 1000).toISOString().replace('T', ' ').slice(0, 16) : `slot ${f.slot}`;
        const line = `${pc.dim(when)}  ${SEVERITY_COLOR[f.severity](f.severity.toUpperCase().padEnd(8))}  ${f.title} ${pc.dim(`· ${f.subjectLabel}`)}`;
        console.log(f.detector === 'attack-chain' ? pc.inverse(line) : line);
        if (severityRank(f.severity) >= severityRank('high')) console.log(pc.dim(`                    ${f.description}`));
    }
}

const COVERAGE_LABEL: Record<CoverageStatus, string> = {
    ran: pc.green('ran'.padEnd(16)),
    'missing-data': pc.yellow('missing data'.padEnd(16)),
    'live-only': pc.yellow('live only'.padEnd(16)),
    'nothing-to-watch': pc.dim('nothing to watch'),
};

function printCoverage(coverage: DetectorCoverage[]): void {
    console.log(`\n${pc.bold('Detector coverage')}`);
    const width = Math.max(...coverage.map((c) => c.detector.length));
    for (const c of coverage) console.log(`  ${COVERAGE_LABEL[c.status]}  ${c.detector.padEnd(width)}  ${pc.dim(c.reason)}`);
    console.log(
        pc.dim(
            "\nReplay starts with no state from before the window: the first signer of each admin instruction becomes its baseline, and proposals created earlier show without their contents. Targets are today's: current multisig members, authorities, admin keys and vault balances.",
        ),
    );
}
