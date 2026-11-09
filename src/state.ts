import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Severity } from './config.js';
import type { AttackStage, Finding } from './detectors/types.js';

interface PendingConfigTransaction {
    multisig: string;
    actions: string[];
    severity: Severity;
    signature: string;
    slot: number;
}

interface ProposedChange {
    multisig: string;
    program: string;
    title: string;
    signature: string;
    slot: number;
}

interface TransactionBuffer {
    /** Hex SHA-256 and byte length Squads checks the finished buffer against. */
    finalHash: string;
    finalSize: number;
    /** Base64 chunks in write order, keyed by the instruction that wrote them, so a replayed transaction adds nothing. */
    chunks: { id: string; data: string }[];
}

interface ProposalRecord {
    multisig: string;
    summary: string;
    /** Proposed calls in order; v3 proposals add them one transaction at a time. */
    steps: string[];
    severity: Severity;
    proposer: string;
    signature: string;
    slot: number;
}

/** What an admin key's signed transactions on a program have looked like so far. */
export interface AdminKeyProfile {
    transactions: number;
    /** Instruction keys from `instructionKey`. */
    instructions: string[];
    /** Fee payers, including the key itself, and co-signers. */
    parties: string[];
    /** Other programs called in the same transactions. */
    programs: string[];
    /** Unix seconds of the last signed call, or of when watching began before any. May be absent in older state files. */
    lastSeen?: number;
    /** Longest time between two signed calls, in seconds. */
    longestGap?: number;
}

type ProfileEntries = Pick<AdminKeyProfile, 'instructions' | 'parties' | 'programs'>;

export interface ChainSignal {
    stage: AttackStage;
    findingId: string;
    title: string;
    slot: number;
}

interface Cursor {
    /** Every matching transaction at or below this slot has been processed. */
    slot: number;
    /** Set once a scan has reached the present; until then, findings are recorded without alerting. */
    caughtUp: boolean;
}

interface StateFile {
    version: 2;
    cursors: Record<string, Cursor>;
    pendingConfigTransactions: Record<string, PendingConfigTransaction>;
    /** Keyed by `programId:normalizedInstruction`. */
    knownSigners: Record<string, string[]>;
    findings: Finding[];
    /** Ids of findings whose alert has not reached every sink yet. */
    pendingAlerts: string[];
    /** Keyed by the Squads transaction or proposal account a later approval references. */
    proposedChanges: Record<string, ProposedChange>;
    /** Recent outflows per `treasury:mint`, raw amounts as decimal strings. */
    outflows: Record<string, { slot: number; amount: string }[]>;
    /** Slot of the last once-per-window alert per key. */
    windowAlerts: Record<string, number>;
    /** Latest IDL activation slot seen per program. */
    idlVersions: Record<string, number>;
    /** Per program: admin key → role. */
    adminKeys: Record<string, Record<string, string>>;
    /** Keyed by the Squads transaction and proposal accounts later instructions reference. */
    proposals: Record<string, ProposalRecord>;
    /** Squads v4 transaction buffers being written, keyed by buffer account; reused buffers start over on create. */
    transactionBuffers: Record<string, TransactionBuffer>;
    /** Recent attack-stage findings per protocol group. */
    chainSignals: Record<string, ChainSignal[]>;
    /** Recent outflow assets per treasury. */
    sweeps: Record<string, { slot: number; asset: string }[]>;
    /** Last decoded field values per config account. */
    /** Decoded config account fields and the slot they were read at. */
    configReads: Record<string, { slot: number; values: Record<string, string> }>;
    /** Keyed by `programId:adminKey`. */
    adminKeyProfiles: Record<string, AdminKeyProfile>;
}

const MAX_FINDINGS = 5_000;
const MAX_PENDING_CONFIG_TRANSACTIONS = 500;
const MAX_PROPOSED_CHANGES = 500;
const MAX_PROPOSALS = 1_000;
const MAX_TRANSACTION_BUFFERS = 200;
const MAX_PROFILE_ENTRIES = 500;

export class StateStore {
    readonly #path: string;
    #state: StateFile;
    #findingIds: Set<string>;
    #dirty = false;

    constructor(path: string) {
        this.#path = path;
        this.#state = load(path);
        this.#findingIds = new Set(this.#state.findings.map((f) => f.id));
    }

    cursor(key: string): Cursor | undefined {
        return this.#state.cursors[key];
    }

    advanceCursor(key: string, slot: number, caughtUp: boolean): void {
        const current = this.#state.cursors[key];
        const next = { slot: Math.max(slot, current?.slot ?? 0), caughtUp: caughtUp || (current?.caughtUp ?? false) };
        if (current && current.slot === next.slot && current.caughtUp === next.caughtUp) return;
        this.#state.cursors[key] = next;
        this.#dirty = true;
    }

    hasFinding(id: string): boolean {
        return this.#findingIds.has(id);
    }

    addFinding(finding: Finding): void {
        this.#findingIds.add(finding.id);
        this.#state.findings.push(finding);
        const overflow = this.#state.findings.length - MAX_FINDINGS;
        if (overflow > 0) {
            for (const dropped of this.#state.findings.splice(0, overflow)) {
                this.#findingIds.delete(dropped.id);
                this.markDelivered(dropped.id);
            }
        }
        this.#dirty = true;
    }

    findings(): readonly Finding[] {
        return this.#state.findings;
    }

    queueAlert(id: string): void {
        if (this.#state.pendingAlerts.includes(id)) return;
        this.#state.pendingAlerts.push(id);
        this.#dirty = true;
    }

    pendingAlerts(): Finding[] {
        const pending = new Set(this.#state.pendingAlerts);
        return this.#state.findings.filter((f) => pending.has(f.id));
    }

    markDelivered(id: string): void {
        const before = this.#state.pendingAlerts.length;
        this.#state.pendingAlerts = this.#state.pendingAlerts.filter((pending) => pending !== id);
        if (this.#state.pendingAlerts.length !== before) this.#dirty = true;
    }

    rememberConfigTransaction(transaction: string, pending: PendingConfigTransaction): void {
        this.#state.pendingConfigTransactions[transaction] = pending;
        dropOldest(this.#state.pendingConfigTransactions, MAX_PENDING_CONFIG_TRANSACTIONS);
        this.#dirty = true;
    }

    configTransaction(transaction: string): PendingConfigTransaction | undefined {
        return this.#state.pendingConfigTransactions[transaction];
    }

    /** Starts or restarts the buffer at `address` with its first chunk; `id` identifies the writing instruction. */
    startTransactionBuffer(address: string, id: string, finalHash: string, finalSize: number, chunk: Uint8Array): void {
        if (this.#state.transactionBuffers[address]?.chunks[0]?.id === id) return;
        delete this.#state.transactionBuffers[address];
        this.#state.transactionBuffers[address] = { finalHash, finalSize, chunks: [{ id, data: Buffer.from(chunk).toString('base64') }] };
        dropOldest(this.#state.transactionBuffers, MAX_TRANSACTION_BUFFERS);
        this.#dirty = true;
    }

    extendTransactionBuffer(address: string, id: string, chunk: Uint8Array): void {
        const buffer = this.#state.transactionBuffers[address];
        if (!buffer || buffer.chunks.some((c) => c.id === id)) return;
        buffer.chunks.push({ id, data: Buffer.from(chunk).toString('base64') });
        this.#dirty = true;
    }

    /** The finished buffer at `address`, or `null` unless it matches the hash and size Squads will check. */
    transactionBuffer(address: string): Uint8Array | null {
        const buffer = this.#state.transactionBuffers[address];
        if (!buffer) return null;
        const bytes = Buffer.concat(buffer.chunks.map((c) => Buffer.from(c.data, 'base64')));
        const matches = bytes.length === buffer.finalSize && createHash('sha256').update(bytes).digest('hex') === buffer.finalHash;
        return matches ? bytes : null;
    }

    rememberProposedChange(keys: string[], change: ProposedChange): void {
        for (const key of keys) this.#state.proposedChanges[key] = change;
        dropOldest(this.#state.proposedChanges, MAX_PROPOSED_CHANGES);
        this.#dirty = true;
    }

    proposedChange(key: string): ProposedChange | undefined {
        return this.#state.proposedChanges[key];
    }

    rememberProposal(keys: string[], proposal: ProposalRecord): void {
        for (const key of keys) this.#state.proposals[key] = proposal;
        dropOldest(this.#state.proposals, MAX_PROPOSALS);
        this.#dirty = true;
    }

    proposal(key: string): ProposalRecord | undefined {
        return this.#state.proposals[key];
    }

    adminKeys(programId: string): Map<string, string> {
        return new Map(Object.entries(this.#state.adminKeys[programId] ?? {}));
    }

    recordAdminKey(programId: string, key: string, role: string): void {
        const keys = (this.#state.adminKeys[programId] ??= {});
        if (keys[key] === role) return;
        keys[key] = role;
        this.#dirty = true;
    }

    configRead(account: string): { slot: number; values: Record<string, string> } | undefined {
        return this.#state.configReads[account];
    }

    setConfigRead(account: string, slot: number, values: Record<string, string>): void {
        this.#state.configReads[account] = { slot, values };
        this.#dirty = true;
    }

    /** Records a signal and returns the group's signals within `windowSlots` of it, including it. */
    recordChainSignal(group: string, signal: ChainSignal, windowSlots: number): ChainSignal[] {
        const kept = (this.#state.chainSignals[group] ?? []).filter(
            (s) => !(s.findingId === signal.findingId && s.stage === signal.stage) && Math.abs(s.slot - signal.slot) < windowSlots * 2,
        );
        kept.push(signal);
        this.#state.chainSignals[group] = kept;
        this.#dirty = true;
        return kept.filter((s) => Math.abs(s.slot - signal.slot) < windowSlots);
    }

    /** Records an outflow of `asset` and returns the distinct assets that left within `windowSlots`. */
    recordSweep(treasury: string, slot: number, asset: string, windowSlots: number): Set<string> {
        const recent = (this.#state.sweeps[treasury] ?? []).filter((o) => o.slot > slot - windowSlots);
        recent.push({ slot, asset });
        this.#state.sweeps[treasury] = recent;
        this.#dirty = true;
        return new Set(recent.map((o) => o.asset));
    }

    /** Records an outflow and returns the total and count within the last `windowSlots`, including it. */
    recordOutflow(key: string, slot: number, amount: bigint, windowSlots: number): { total: bigint; count: number } {
        const recent = (this.#state.outflows[key] ?? []).filter((o) => o.slot > slot - windowSlots);
        recent.push({ slot, amount: amount.toString() });
        this.#state.outflows[key] = recent;
        this.#dirty = true;
        return { total: recent.reduce((sum, o) => sum + BigInt(o.amount), 0n), count: recent.length };
    }

    /** True at most once per window for each key. */
    claimWindowAlert(key: string, slot: number, windowSlots: number): boolean {
        const last = this.#state.windowAlerts[key];
        if (last !== undefined && slot - last < windowSlots) return false;
        this.#state.windowAlerts[key] = slot;
        this.#dirty = true;
        return true;
    }

    idlVersion(programId: string): number | undefined {
        return this.#state.idlVersions[programId];
    }

    setIdlVersion(programId: string, slot: number): void {
        this.#state.idlVersions[programId] = slot;
        this.#dirty = true;
    }

    /**
     * Adds one transaction to the profile at `key` and returns the profile as it was before it, or `undefined` for the
     * first. Each list keeps its first `MAX_PROFILE_ENTRIES` entries, so later additions stay reported as new.
     */
    recordAdminKeyUse(key: string, use: ProfileEntries, time: number): AdminKeyProfile | undefined {
        const current = this.#state.adminKeyProfiles[key];
        const before = current && structuredClone(current);
        const profile: AdminKeyProfile = current ?? { transactions: 0, instructions: [], parties: [], programs: [] };
        if (profile.lastSeen === undefined || time > profile.lastSeen) {
            if (profile.transactions > 0 && profile.lastSeen !== undefined) {
                profile.longestGap = Math.max(profile.longestGap ?? 0, time - profile.lastSeen);
            }
            profile.lastSeen = time;
        }
        profile.transactions++;
        for (const field of ['instructions', 'parties', 'programs'] as const) {
            for (const entry of use[field]) {
                if (!profile[field].includes(entry) && profile[field].length < MAX_PROFILE_ENTRIES) profile[field].push(entry);
            }
        }
        this.#state.adminKeyProfiles[key] = profile;
        this.#dirty = true;
        return before;
    }

    /** Starts an empty profile at `key` watched since `since` (unix seconds), unless one exists. */
    startAdminKeyProfile(key: string, since: number): void {
        if (this.#state.adminKeyProfiles[key]) return;
        this.#state.adminKeyProfiles[key] = { transactions: 0, instructions: [], parties: [], programs: [], lastSeen: since };
        this.#dirty = true;
    }

    knownSigners(key: string): readonly string[] {
        return this.#state.knownSigners[key] ?? [];
    }

    /** Returns signers not seen before for `key`. The first non-empty call sets the baseline and returns none. */
    recordSigners(key: string, signers: string[]): string[] {
        const unique = [...new Set(signers)];
        if (unique.length === 0) return [];
        const known = this.#state.knownSigners[key];
        if (!known) {
            this.#state.knownSigners[key] = unique;
            this.#dirty = true;
            return [];
        }
        const unseen = unique.filter((signer) => !known.includes(signer));
        if (unseen.length > 0) {
            known.push(...unseen);
            this.#dirty = true;
        }
        return unseen;
    }

    save(): void {
        if (!this.#dirty) return;
        mkdirSync(dirname(this.#path), { recursive: true });
        const temp = `${this.#path}.tmp`;
        writeFileSync(temp, JSON.stringify(this.#state, null, 2));
        renameSync(temp, this.#path);
        this.#dirty = false;
    }
}

function dropOldest(record: Record<string, unknown>, max: number): void {
    const keys = Object.keys(record);
    for (const key of keys.slice(0, Math.max(0, keys.length - max))) delete record[key];
}

function load(path: string): StateFile {
    if (!existsSync(path)) return emptyState();
    let parsed: Partial<StateFile>;
    try {
        parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<StateFile>;
    } catch (error) {
        throw new Error(`State file ${path} is not valid JSON (${(error as Error).message}). Delete it to start over.`);
    }
    if (parsed.version !== 2) {
        throw new Error(`State file ${path} is from an older Watchtower version. Delete it to start over.`);
    }
    return { ...emptyState(), ...parsed };
}

function emptyState(): StateFile {
    return {
        version: 2,
        cursors: {},
        pendingConfigTransactions: {},
        knownSigners: {},
        findings: [],
        pendingAlerts: [],
        proposedChanges: {},
        outflows: {},
        windowAlerts: {},
        idlVersions: {},
        adminKeys: {},
        proposals: {},
        transactionBuffers: {},
        chainSignals: {},
        sweeps: {},
        configReads: {},
        adminKeyProfiles: {},
    };
}
