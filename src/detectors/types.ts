import type { Severity } from '../config.js';
import type { ParsedInstruction, ParsedTx } from '../model.js';
import type { StateStore } from '../state.js';

export interface Finding {
    /** Stable across backfill and live delivery of the same event. */
    id: string;
    detector: string;
    severity: Severity;
    title: string;
    description: string;
    /** The watched program, multisig, mint or treasury address. */
    subject: string;
    subjectLabel: string;
    /** `null` when not tied to a transaction, such as an IDL change. */
    signature: string | null;
    slot: number;
    blockTime: number | null;
    details: Record<string, string>;
    stages?: AttackStage[];
}

export type AttackStage = 'control' | 'risk' | 'drain';

export interface WatchedProgram {
    id: string;
    label: string;
    programData: string | null;
    /** Normalized with `normalizeName`. */
    privilegedInstructions: Set<string>;
    /** IDL instruction names keyed by hex discriminator. */
    instructionsByDiscriminator: Map<string, string>;
    adminKeys: string[];
}

export interface WatchedMultisig {
    address: string;
    label: string;
    version: 3 | 4 | null;
    threshold: number | null;
    timeLockSeconds: number | null;
}

export interface WatchedMint {
    address: string;
    label: string;
    supply: bigint | null;
    decimals: number | null;
    permanentDelegate: string | null;
}

/** A Token-2022 account of a watched treasury or vault whose mint's permanent delegate can move or burn its tokens. */
export interface SeizableAccount {
    tokenAccount: string;
    mint: string;
    delegate: string;
    /** The treasury or vault address that owns the token account. */
    owner: string;
}

export interface WatchedTreasury {
    address: string;
    label: string;
    /** Keyed by mint address, or `SOL` for native SOL; values in UI units. */
    thresholds: Map<string, number>;
    alertOnAnyOutflow: boolean;
    windowSlots: number;
    /** When non-empty, any outflow to another address alerts. */
    allowedDestinations: Set<string>;
    /** Auto-discovered vault: only outflows at a holding's threshold count toward a sweep. */
    discovered: boolean;
}

/** Upgrade authority, multisig member, mint authority or admin signer of a watched subject. */
export interface PrivilegedKey {
    address: string;
    role: string;
    subject: string;
    subjectLabel: string;
}

/** A wallet holding funds or stake; authority hand-offs it signs alert. */
export interface CustodyKey {
    address: string;
    label: string;
    subject: string;
    subjectLabel: string;
}

export interface WatchTargets {
    programs: Map<string, WatchedProgram>;
    programsByProgramData: Map<string, WatchedProgram>;
    multisigs: Map<string, WatchedMultisig>;
    mints: Map<string, WatchedMint>;
    treasuries: Map<string, WatchedTreasury>;
    /** Keyed by token account. */
    seizableAccounts: Map<string, SeizableAccount>;
    privilegedKeys: Map<string, PrivilegedKey>;
    custodyKeys: Map<string, CustodyKey>;
    /** Subject → its protocol group: a program ID, or the subject itself. */
    groups: Map<string, string>;
}

export interface DetectorContext {
    targets: WatchTargets;
    state: StateStore;
    slotMs: number;
}

export interface Detector {
    id: string;
    description: string;
    includeFailed?: boolean;
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[];
}

type FindingFields = Omit<Finding, 'id' | 'detector' | 'signature' | 'slot' | 'blockTime'>;

export function findingFor(detector: string, tx: ParsedTx, ix: ParsedInstruction, fields: FindingFields): Finding {
    return txFinding(detector, tx, `${ix.instructionIndex}.${ix.innerInstructionIndex ?? '-'}`, fields);
}

export type FindingAnchor = { signature: string | null; slot: number; blockTime: number | null };

/** `key` distinguishes several findings from one detector in the same transaction. */
export function txFinding(detector: string, tx: FindingAnchor, key: string, fields: FindingFields): Finding {
    return {
        id: `${detector}:${tx.signature ?? `slot-${tx.slot}`}:${key}`,
        detector,
        signature: tx.signature,
        slot: tx.slot,
        blockTime: tx.blockTime,
        ...fields,
    };
}
