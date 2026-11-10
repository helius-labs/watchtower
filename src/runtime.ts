import type { Config } from './config.js';
import { FALLBACK_SLOT_MS } from './constants.js';
import type { DetectorContext, Finding } from './detectors/types.js';
import {
    discoverAdmins,
    discoverConfigAccounts,
    discoverMint,
    discoverProgram,
    discoverTokenAccounts,
    discoverVaults,
    loadMultisig,
    type ProgramState,
} from './discover/index.js';
import { Engine } from './engine.js';
import { ParsedEventsClient } from './helius/parsedEvents.js';
import { RpcClient } from './helius/rpc.js';
import { heliusClient } from './helius/sdk.js';
import { createSinks } from './sinks.js';
import { StateStore } from './state.js';
import { buildTargets, scanPlans, type Discovery, type ScanPlan } from './targets.js';
import { createEnricher } from './vet.js';

export interface Runtime {
    config: Config;
    rpc: RpcClient;
    events: ParsedEventsClient;
    state: StateStore;
    discovery: Discovery;
    ctx: DetectorContext;
    engine: Engine;
    plans: ScanPlan[];
    slotMs: number;
}

export interface RuntimeOptions {
    onRecord?: (finding: Finding) => void;
    /** Discover with the IDL live at this slot. */
    idlAtSlot?: number;
}

export async function createRuntime(config: Config, options: RuntimeOptions = {}): Promise<Runtime> {
    const { onRecord, idlAtSlot } = options;
    const helius = heliusClient(config.apiKey, config.endpoints);
    const rpc = new RpcClient(helius);
    const events = new ParsedEventsClient(helius, config.apiKey);
    const state = new StateStore(config.stateFile);
    const [discovery, slotMs] = await Promise.all([
        discoverAll(config, rpc, events, state, idlAtSlot),
        rpc.getSlotDurationMs().catch((error: Error) => {
            console.warn(`Failed to measure slot time, assuming ${FALLBACK_SLOT_MS} ms: ${error.message}`);
            return FALLBACK_SLOT_MS;
        }),
    ]);
    const targets = buildTargets(config, discovery, state, slotMs);
    const ctx: DetectorContext = { targets, state, slotMs };
    const engine = new Engine(
        ctx,
        createSinks(config.alerts.sinks, config.alerts.minSeverity),
        onRecord,
        createEnricher(rpc, events, (id) => ctx.targets.programs.get(id)?.programData ?? null),
        config.alerts.groupWindowSeconds * 1000,
    );
    return { config, rpc, events, state, discovery, ctx, engine, plans: scanPlans(config, targets), slotMs };
}

/** Replaces `ctx.targets` and `plans` in place: read them from the runtime, never from a copy. */
export async function refreshDiscovery(runtime: Runtime): Promise<void> {
    const discovery = await discoverAll(runtime.config, runtime.rpc, runtime.events, runtime.state);
    runtime.discovery = discovery;
    runtime.ctx.targets = buildTargets(runtime.config, discovery, runtime.state, runtime.slotMs);
    runtime.plans = scanPlans(runtime.config, runtime.ctx.targets);
}

async function discoverAll(
    config: Config,
    rpc: RpcClient,
    events: ParsedEventsClient,
    state: StateStore,
    idlAtSlot?: number,
): Promise<Discovery> {
    const [programs, mints, multisigs] = await Promise.all([
        Promise.all(
            config.programs.map(async (p) => {
                const program = await discoverProgram(rpc, events, p.id, idlAtSlot);
                return withAuthorities(program, p.privilegedInstructions, p.watchVaults, rpc, events, state);
            }),
        ),
        Promise.all(config.mints.map((m) => discoverMint(rpc, m.address))),
        Promise.all(config.multisigs.map((m) => loadMultisig(rpc, m.address))),
    ]);
    const owners = [...config.treasuries.map((t) => t.address), ...programs.flatMap((p) => p.vaults.map((v) => v.authority))];
    const tokenAccounts = await discoverTokenAccounts(rpc, owners).catch((error: Error) => {
        console.warn(`Failed to list the token accounts of treasuries and vaults: ${error.message}`);
        return [];
    });
    return { programs, mints, multisigs, tokenAccounts };
}

async function withAuthorities(
    program: ProgramState,
    privileged: string[],
    watchVaults: boolean,
    rpc: RpcClient,
    events: ParsedEventsClient,
    state: StateStore,
): Promise<ProgramState> {
    const { accounts: configAccounts, unlocated } = await discoverConfigAccounts(rpc, events, program.programId, program.idl).catch(
        (error: Error) => {
            console.warn(`Failed to read config accounts of ${program.programId}: ${error.message}`);
            return { accounts: [], unlocated: [] };
        },
    );
    const [admins, vaults] = await Promise.all([
        discoverAdmins(rpc, events, program.programId, configAccounts, privileged, state.adminKeys(program.programId)).catch(
            (error: Error) => {
                console.warn(`Failed to find admin keys for ${program.programId}: ${error.message}`);
                return [];
            },
        ),
        watchVaults
            ? discoverVaults(rpc, events, program.programId).catch((error: Error) => {
                  console.warn(`Failed to find vaults for ${program.programId}: ${error.message}`);
                  return [];
              })
            : [],
    ]);
    // Integration accounts also have "authority" fields; keep only accounts whose admin field is a discovered admin.
    const adminKeys = new Set(admins.map((a) => a.key));
    const configs = configAccounts.filter((c) => c.layout.fields.some((f) => f.admin && adminKeys.has(c.values[f.name] ?? '')));
    return { ...program, admins, vaults, configAccounts: configs, unlocatedConfigs: unlocated };
}
