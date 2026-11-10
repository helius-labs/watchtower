import { formatAmount, parseUnits, short, toBigInt } from '../format.js';
import type { ParsedTx } from '../model.js';
import { txFinding, type Detector, type DetectorContext, type Finding, type WatchedTreasury } from './types.js';

const ID = 'treasury-outflow';
/** A window total at this multiple of the per-transaction threshold is a sustained drain. */
const SUSTAINED_MULTIPLE = 3n;
/** Distinct assets leaving within the window that make a sweep. */
const SWEEP_ASSETS = 3;
const SOL = 'SOL';

interface Outflow {
    amount: bigint;
    decimals: number;
    recipients: Set<string>;
    /** Signers other than the treasury, by the token account they moved tokens out of. */
    delegates: Map<string, string>;
}

export const treasuryOutflow: Detector = {
    id: ID,
    description: 'Large, sustained, multi-asset and unexpected-destination outflows from treasuries and program vaults',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const treasury of ctx.targets.treasuries.values()) {
            const outflows = outflowsFrom(tx, treasury);
            for (const [mint, outflow] of outflows) {
                findings.push(...judge(tx, ctx, treasury, mint, outflow));
                const threshold = treasury.thresholds.get(mint);
                const significant =
                    threshold === undefined ? !treasury.discovered : outflow.amount >= parseUnits(threshold, outflow.decimals);
                const sweep = significant ? sweepFinding(tx, ctx, treasury, mint) : null;
                if (sweep) findings.push(sweep);
            }
        }
        return findings.map((f) => (f.severity === 'high' || f.severity === 'critical' ? { ...f, stages: ['drain' as const] } : f));
    },
};

function sweepFinding(tx: ParsedTx, ctx: DetectorContext, treasury: WatchedTreasury, mint: string): Finding | null {
    const assets = ctx.state.recordSweep(treasury.address, tx.slot, mint, treasury.windowSlots);
    if (assets.size < SWEEP_ASSETS || !ctx.state.claimWindowAlert(`${treasury.address}:sweep`, tx.slot, treasury.windowSlots)) return null;
    const names = [...assets].map((a) => (a === SOL ? 'SOL' : short(a)));
    return txFinding(ID, tx, 'sweep', {
        severity: 'critical',
        title: 'Multi-asset sweep',
        description: `${assets.size} different assets left ${treasury.label} within the alert window (${names.join(', ')}). Emptying many assets at once is how hot-wallet thefts like Upbit's in November 2025 look.`,
        subject: treasury.address,
        subjectLabel: treasury.label,
        details: { Assets: names.join(', ') },
    });
}

function judge(tx: ParsedTx, ctx: DetectorContext, treasury: WatchedTreasury, mint: string, outflow: Outflow): Finding[] {
    const asset = mint === SOL ? 'SOL' : short(mint);
    const amountText = `${formatAmount(outflow.amount, outflow.decimals)} ${asset}`;
    const threshold = treasury.thresholds.get(mint);
    const thresholdRaw = threshold === undefined ? null : parseUnits(threshold, outflow.decimals);
    const key = `${treasury.address}:${mint}`;
    const rolling = ctx.state.recordOutflow(key, tx.slot, outflow.amount, treasury.windowSlots);
    const details = {
        Asset: mint === SOL ? 'Native SOL' : mint,
        Amount: amountText,
        Recipients: [...outflow.recipients].join(', ') || 'unknown',
        ...(threshold === undefined ? {} : { Threshold: `${threshold} ${asset}` }),
    };
    const base = { subject: treasury.address, subjectLabel: treasury.label };
    const findings: Finding[] = [];

    const delegated = [...outflow.delegates].filter(([account, signer]) => ctx.targets.seizableAccounts.get(account)?.delegate !== signer);
    if (delegated.length > 0) {
        const signers = [...new Set(delegated.map(([, signer]) => signer))].join(', ');
        findings.push(
            txFinding(ID, tx, `${mint}:delegate`, {
                ...base,
                severity: 'high',
                title: 'Outflow signed by a delegate',
                description: `${amountText} left ${treasury.label} in a transfer signed by ${signers}, not by ${treasury.label}. A delegate approved on a token account can move tokens up to its allowance without the owner signing again.`,
                details: { ...details, Delegate: signers, 'Token account': delegated.map(([account]) => account).join(', ') },
            }),
        );
    }

    const unlisted = [...outflow.recipients].filter((r) => treasury.allowedDestinations.size > 0 && !treasury.allowedDestinations.has(r));
    if (unlisted.length > 0) {
        findings.push(
            txFinding(ID, tx, `${mint}:destination`, {
                ...base,
                severity: 'high',
                title: 'Outflow to an unlisted destination',
                description: `${amountText} left ${treasury.label} for ${unlisted.join(', ')}, which is not on its allowed destinations list.`,
                details: { ...details, 'Unlisted destinations': unlisted.join(', ') },
            }),
        );
    }

    if (thresholdRaw !== null && outflow.amount >= thresholdRaw) {
        findings.push(
            txFinding(ID, tx, mint, {
                ...base,
                severity: 'high',
                title: 'Large treasury outflow',
                description: `${amountText} left ${treasury.label} in one transaction.`,
                details,
            }),
        );
    } else if (treasury.alertOnAnyOutflow) {
        findings.push(
            txFinding(ID, tx, mint, {
                ...base,
                severity: 'low',
                title: 'Treasury outflow',
                description: `${amountText} left ${treasury.label}.`,
                details,
            }),
        );
    }

    if (
        thresholdRaw !== null &&
        rolling.count > 1 &&
        rolling.total >= thresholdRaw * SUSTAINED_MULTIPLE &&
        ctx.state.claimWindowAlert(key, tx.slot, treasury.windowSlots)
    ) {
        findings.push(
            txFinding(ID, tx, `${mint}:sustained`, {
                ...base,
                severity: 'critical',
                title: 'Sustained treasury outflow',
                description: `${formatAmount(rolling.total, outflow.decimals)} ${asset} left ${treasury.label} across ${rolling.count} transactions within the alert window, at least ${SUSTAINED_MULTIPLE}× the per-transaction threshold.`,
                details: { ...details, 'Window total': `${formatAmount(rolling.total, outflow.decimals)} ${asset}` },
            }),
        );
    }
    return findings;
}

/**
 * Net raw outflow per mint (`SOL` for native): what left minus what came back in the same transaction. A token
 * transfer's `fromUserAccount` is its signer, so one a delegate signs is matched by the treasury's token account.
 */
function outflowsFrom(tx: ParsedTx, treasury: WatchedTreasury): Map<string, Outflow> {
    const { address, tokenAccounts } = treasury;
    const outflows = new Map<string, Outflow>();
    const add = (mint: string, amount: bigint | null, decimals: number, recipient: string | null) => {
        if (amount === null || amount === 0n) return undefined;
        const entry = outflows.get(mint) ?? { amount: 0n, decimals, recipients: new Set<string>(), delegates: new Map<string, string>() };
        entry.amount += amount;
        if (recipient && amount > 0n) entry.recipients.add(recipient);
        outflows.set(mint, entry);
        return entry;
    };
    for (const t of tx.nativeTransfers) {
        if (t.fromUserAccount === address && t.toUserAccount !== address) add(SOL, toBigInt(t.amount), 9, t.toUserAccount);
        if (t.toUserAccount === address && t.fromUserAccount !== address) add(SOL, negate(toBigInt(t.amount)), 9, null);
    }
    for (const t of tx.tokenTransfers) {
        const fromAccount = t.fromTokenAccount !== null && tokenAccounts.has(t.fromTokenAccount);
        const fromTreasury = t.fromUserAccount === address || t.fromTokenAccount === address || fromAccount;
        const toTreasury =
            t.toUserAccount === address ||
            t.toTokenAccount === address ||
            (t.toTokenAccount !== null && tokenAccounts.has(t.toTokenAccount));
        if (fromTreasury && !toTreasury) {
            const entry = add(t.mint, toBigInt(t.rawTokenAmount), t.decimals, t.toUserAccount ?? t.toTokenAccount);
            if (entry && fromAccount && t.fromUserAccount && t.fromUserAccount !== address)
                entry.delegates.set(t.fromTokenAccount!, t.fromUserAccount);
        }
        if (toTreasury && !fromTreasury) add(t.mint, negate(toBigInt(t.rawTokenAmount)), t.decimals, null);
    }
    for (const [mint, outflow] of outflows) if (outflow.amount <= 0n) outflows.delete(mint);
    return outflows;
}

function negate(amount: bigint | null): bigint | null {
    return amount === null ? null : -amount;
}
