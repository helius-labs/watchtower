import { getBase58Encoder } from '@solana/kit';
import type { Severity } from '../config.js';
import { PROGRAMS } from '../constants.js';
import { humanDuration, short } from '../format.js';
import { normalizeName, type ParsedInstruction, type ParsedTx } from '../model.js';
import type { AdminKeyProfile, StateStore } from '../state.js';
import type { ScanPlan } from '../targets.js';
import { txFinding, type Detector, type DetectorContext, type Finding, type WatchedProgram } from './types.js';

const ID = 'admin-key-behavior';
/** Transactions a profile needs before departures from it are reported. Dormancy needs none. */
const MIN_BASELINE_TRANSACTIONS = 10;
const DORMANT_SECONDS = 21 * 86_400;
const DORMANT_GAP_MULTIPLE = 3;
/** Programs found in transactions of every kind, so they say nothing about who built one. */
const COMMON_PROGRAMS = new Set<string>([
    PROGRAMS.system,
    PROGRAMS.splToken,
    PROGRAMS.token2022,
    'ComputeBudget111111111111111111111111111111',
    'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
    'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',
    'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo',
]);
/** Normalized names such as marginfi's `lending_account_start_flashloan` and Kamino's `flash_borrow_reserve_liquidity`. */
const FLASH_LOAN = /flash(loan|borrow)/;

interface Signal {
    strong: boolean;
    text: string;
}

export const adminKeyBehavior: Detector = {
    id: ID,
    description:
        "A known admin key used in a way its own history doesn't show: after a long quiet spell, a new instruction, a flash loan, a new fee payer or co-signer, or a new program alongside",
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        const signed = transactionSigners(tx);
        for (const program of ctx.targets.programs.values()) {
            const calls = tx.instructions.filter((ix) => ix.programId === program.id);
            if (calls.length === 0) continue;
            for (const key of program.adminKeys) {
                if (!signed.has(key) && !calls.some((ix) => isUndecodedTopLevel(ix) && ix.rawAccounts?.includes(key))) continue;
                const use = {
                    instructions: [...new Set(calls.filter((ix) => involves(ix, key)).map((ix) => instructionKey(ix, program)))],
                    parties: [...new Set([...(tx.feePayer ? [tx.feePayer] : []), ...[...signed].filter((s) => s !== key)])],
                    programs: [...new Set(tx.instructions.map((ix) => ix.programId))].filter(
                        (p) => p !== program.id && !COMMON_PROGRAMS.has(p),
                    ),
                };
                const time = tx.blockTime ?? Math.floor(Date.now() / 1000);
                const before = ctx.state.recordAdminKeyUse(profileKey(program.id, key), use, time);
                const signals = [...dormancy(before, time), ...departures(key, use, before, tx), ...flashLoans(tx, before)];
                if (signals.length > 0) findings.push(finding(tx, program, key, signals));
            }
        }
        return findings;
    },
};

function profileKey(programId: string, key: string): string {
    return `${programId}:${key}`;
}

/**
 * Starts the profile of `plan`'s admin key as watched since `since` (unix seconds), so its first signed call after a
 * long quiet spell counts as dormant even when the scan found none before it.
 */
export function startAdminKeyProfile(state: StateStore, plan: ScanPlan, since: number): void {
    if (plan.detectors.includes(ID)) state.startAdminKeyProfile(profileKey(plan.subject, plan.address), since);
}

/** A first signed call after at least `DORMANT_SECONDS`, and at least `DORMANT_GAP_MULTIPLE` times its longest earlier quiet spell. */
function dormancy(before: AdminKeyProfile | undefined, time: number): Signal[] {
    if (before?.lastSeen === undefined) return [];
    const gap = time - before.lastSeen;
    const longest = before.longestGap ?? 0;
    if (gap < Math.max(DORMANT_SECONDS, DORMANT_GAP_MULTIPLE * longest)) return [];
    const text =
        before.transactions === 0
            ? `was its first signed call in the ${humanDuration(gap)} Watchtower has watched it`
            : `came ${humanDuration(gap)} after its previous signed call${longest > 0 ? `, when its longest quiet spell before was ${humanDuration(longest)}` : ''}`;
    return [{ strong: true, text }];
}

/**
 * The fee payer and signers of decoded top-level instructions. Inner instructions also mark PDAs that sign through CPI,
 * which hold no private key. Neither API sends transaction-level signers, and undecoded instructions carry no signer
 * flags, so an admin key passed to an undecoded top-level call of its program is counted as signing it.
 */
function transactionSigners(tx: ParsedTx): Set<string> {
    const signed = new Set(tx.feePayer ? [tx.feePayer] : []);
    for (const ix of tx.instructions) {
        if (ix.innerInstructionIndex !== null) continue;
        for (const a of ix.accounts ?? []) if (a.isSigner) signed.add(a.pubkey);
    }
    return signed;
}

function isUndecodedTopLevel(ix: ParsedInstruction): boolean {
    return ix.innerInstructionIndex === null && ix.accounts === null;
}

function involves(ix: ParsedInstruction, key: string): boolean {
    return (ix.accounts?.some((a) => a.pubkey === key) ?? false) || (ix.rawAccounts?.includes(key) ?? false);
}

/** The normalized name, else `#` and the hex discriminator, or the first byte when the program has no IDL. */
export function instructionKey(ix: ParsedInstruction, program: WatchedProgram): string {
    if (ix.instructionName) return normalizeName(ix.instructionName);
    const data = ix.rawData ? Uint8Array.from(getBase58Encoder().encode(ix.rawData)) : new Uint8Array();
    if (program.instructionsByDiscriminator.size > 0 && data.length >= 8) {
        const hex = Buffer.from(data.subarray(0, 8)).toString('hex');
        const name = program.instructionsByDiscriminator.get(hex);
        return name ? normalizeName(name) : `#${hex}`;
    }
    return `#${data[0] ?? '?'}`;
}

function departures(
    key: string,
    use: Pick<AdminKeyProfile, 'instructions' | 'parties' | 'programs'>,
    before: AdminKeyProfile | undefined,
    tx: ParsedTx,
): Signal[] {
    if (!before || before.transactions < MIN_BASELINE_TRANSACTIONS) return [];
    const newInstructions = use.instructions.filter((i) => !before.instructions.includes(i));
    const newParties = use.parties.filter((p) => !before.parties.includes(p));
    const newPrograms = use.programs.filter((p) => !before.programs.includes(p));
    const programName = (id: string) => tx.instructions.find((ix) => ix.programId === id && ix.programName)?.programName ?? short(id);
    const seen = `in ${before.transactions.toLocaleString('en-US')} earlier transactions`;
    return [
        ...(newInstructions.length > 0
            ? [{ strong: true, text: `called ${newInstructions.map(describeInstruction).join(', ')}, which it had not ${seen}` }]
            : []),
        ...(newParties.length > 0
            ? [
                  {
                      strong: false,
                      text: `had ${newParties.map((p) => (p === key ? 'itself paying the fee' : short(p))).join(', ')} as fee payer or co-signer, not seen ${seen}`,
                  },
              ]
            : []),
        ...(newPrograms.length > 0
            ? [{ strong: false, text: `also called ${newPrograms.map(programName).join(', ')}, not used with it ${seen}` }]
            : []),
    ];
}

/** Not reported when the key's history already includes the lending program. */
function flashLoans(tx: ParsedTx, before: AdminKeyProfile | undefined): Signal[] {
    const loan = tx.instructions.find((ix) => ix.instructionName && FLASH_LOAN.test(normalizeName(ix.instructionName)));
    if (!loan || (before && before.transactions >= MIN_BASELINE_TRANSACTIONS && before.programs.includes(loan.programId))) return [];
    return [{ strong: true, text: `ran inside a flash loan (${loan.instructionName} on ${loan.programName ?? short(loan.programId)})` }];
}

function describeInstruction(key: string): string {
    return key.startsWith('#') ? `undecoded instruction ${key.slice(1)}` : key;
}

function finding(tx: ParsedTx, program: WatchedProgram, key: string, signals: Signal[]): Finding {
    const strong = signals.filter((s) => s.strong).length;
    const severity: Severity = strong > 0 ? (signals.length > 1 ? 'critical' : 'high') : signals.length > 1 ? 'medium' : 'low';
    return txFinding(ID, tx, `${program.id}:${key}`, {
        severity,
        title: strong > 0 ? 'Admin key used in an unfamiliar way' : 'Admin key used with something new',
        description: `${key}, an admin key of ${program.label}, signed a transaction that ${signals.map((s) => s.text).join('; ')}. A stolen key often shows up this way first.`,
        subject: program.id,
        subjectLabel: program.label,
        details: {
            'Admin key': key,
            'Fee payer': tx.feePayer ?? 'unknown',
            ...Object.fromEntries(signals.map((s, i) => [`Signal ${i + 1}`, s.text])),
        },
        ...(severity === 'high' || severity === 'critical' ? { stages: ['control' as const] } : {}),
    });
}
