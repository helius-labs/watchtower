import { getBase58Decoder } from '@solana/kit';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PROGRAMS } from '../src/constants.js';
import type { DetectorContext, WatchTargets } from '../src/detectors/types.js';
import { fromStream, normalizeName, type NativeTransfer, type ParsedTx, type TokenTransfer } from '../src/model.js';
import { StateStore } from '../src/state.js';

export const KEYS = {
    program: 'Prog111111111111111111111111111111111111111',
    programData: 'PData11111111111111111111111111111111111111',
    vault: 'Vau1t1111111111111111111111111111111111111',
    multisig: 'Mu1tisig111111111111111111111111111111111',
    member: 'Member1111111111111111111111111111111111111',
    attacker: 'Attacker111111111111111111111111111111111',
    buffer: 'Buffer11111111111111111111111111111111111111',
    mint: 'Mint111111111111111111111111111111111111111',
    configTx: 'ConfigTx11111111111111111111111111111111111',
    proposal: 'Proposa111111111111111111111111111111111111',
    treasury: 'Treasury11111111111111111111111111111111111',
    nonce: 'Nonce11111111111111111111111111111111111111',
};

export interface IxSpec {
    programId: string;
    name: string | null;
    accounts?: [name: string, pubkey: string, isSigner?: boolean][];
    args?: Record<string, unknown>;
    inner?: IxSpec[];
    /** An instruction the parser could not decode: sent as `rawData` and `rawAccounts` only. */
    raw?: { data: Uint8Array; accounts: string[] };
}

export interface TxOptions {
    failed?: boolean;
    feePayer?: string;
    nativeTransfers?: NativeTransfer[];
    tokenTransfers?: TokenTransfer[];
}

/** Builds a transaction in the Parsed Streams wire shape and converts it like `watch` does. */
export function tx(signature: string, slot: number, instructions: IxSpec[], options: TxOptions = {}): ParsedTx {
    const wire = instructions.flatMap((top, instructionIndex) => [
        wireIx(top, instructionIndex, null),
        ...(top.inner ?? []).map((inner, innerIndex) => wireIx(inner, instructionIndex, innerIndex)),
    ]);
    return fromStream({
        transaction: {
            signature,
            slot,
            blockTime: null,
            feePayer: options.feePayer ?? KEYS.member,
            status: options.failed ? 'error' : 'ok',
            fee: 5_000,
            accountKeys: [],
            summary: null,
            error: options.failed ? { InstructionError: [0, { Custom: 6000 }] } : null,
            nativeTransfers: options.nativeTransfers ?? [],
            tokenTransfers: options.tokenTransfers ?? [],
        },
        instructions: wire,
    });
}

function wireIx(spec: IxSpec, instructionIndex: number, innerInstructionIndex: number | null) {
    if (spec.raw) {
        return {
            instructionIndex,
            innerInstructionIndex,
            stackHeight: innerInstructionIndex === null ? 1 : 2,
            programId: spec.programId,
            programName: null,
            instructionName: null,
            summary: null,
            decoded: null,
            rawData: getBase58Decoder().decode(spec.raw.data),
            rawAccounts: spec.raw.accounts,
        };
    }
    return {
        instructionIndex,
        innerInstructionIndex,
        stackHeight: innerInstructionIndex === null ? 1 : 2,
        programId: spec.programId,
        programName: null,
        instructionName: spec.name,
        summary: null,
        decoded: {
            args: spec.args ?? {},
            accounts: (spec.accounts ?? []).map(([name, pubkey, isSigner]) => ({
                name,
                pubkey,
                isSigner: isSigner ?? false,
                isWritable: true,
            })),
        },
    };
}

export function context(
    overrides: Partial<{
        privileged: string[];
        mintSupply: bigint;
        thresholds: Record<string, number>;
        permanentDelegate: string;
        treasuryTokenAccounts: string[];
    }> = {},
): DetectorContext {
    const program = {
        id: KEYS.program,
        label: 'Test Program',
        programData: KEYS.programData,
        privilegedInstructions: new Set((overrides.privileged ?? []).map(normalizeName)),
        instructionsByDiscriminator: new Map<string, string>(),
        adminKeys: [],
    };
    const targets: WatchTargets = {
        programs: new Map([[program.id, program]]),
        programsByProgramData: new Map([[KEYS.programData, program]]),
        multisigs: new Map([
            [KEYS.multisig, { address: KEYS.multisig, label: 'Upgrade multisig', version: 4, threshold: 3, timeLockSeconds: 86_400 }],
        ]),
        mints: new Map([
            [
                KEYS.mint,
                {
                    address: KEYS.mint,
                    label: 'TEST',
                    supply: overrides.mintSupply ?? 1_000_000_000n,
                    decimals: 6,
                    permanentDelegate: overrides.permanentDelegate ?? null,
                },
            ],
        ]),
        treasuries: new Map([
            [
                KEYS.treasury,
                {
                    address: KEYS.treasury,
                    label: 'Treasury',
                    thresholds: new Map(Object.entries(overrides.thresholds ?? { SOL: 100 })),
                    alertOnAnyOutflow: false,
                    windowSlots: 9_000,
                    allowedDestinations: new Set<string>(),
                    discovered: false,
                    tokenAccounts: new Set(overrides.treasuryTokenAccounts ?? []),
                    delegates: new Map<string, string>(),
                },
            ],
        ]),
        seizableAccounts: new Map(),
        privilegedKeys: new Map([
            [
                KEYS.member,
                { address: KEYS.member, role: 'Member of Upgrade multisig', subject: KEYS.multisig, subjectLabel: 'Upgrade multisig' },
            ],
        ]),
        custodyKeys: new Map([
            [KEYS.treasury, { address: KEYS.treasury, label: 'Treasury', subject: KEYS.treasury, subjectLabel: 'Treasury' }],
        ]),
        groups: new Map([
            [KEYS.program, KEYS.program],
            [KEYS.multisig, KEYS.program],
            [KEYS.treasury, KEYS.program],
        ]),
    };
    const dir = mkdtempSync(join(tmpdir(), 'watchtower-test-'));
    return { targets, state: new StateStore(join(dir, 'state.json')), slotMs: 400 };
}

export const loaderUpgrade: IxSpec = {
    programId: PROGRAMS.bpfLoaderUpgradeable,
    name: 'upgrade',
    accounts: [
        ['program_data_account', KEYS.programData],
        ['program_account', KEYS.program],
        ['buffer_account', KEYS.buffer],
        ['spill_account', KEYS.member],
        ['authority', KEYS.vault, true],
    ],
};
