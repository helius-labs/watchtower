import type { Severity } from '../config.js';
import { PROGRAMS } from '../constants.js';
import { account, arg, nameOf, normalizeName, pubkeyArg, signers, type ParsedInstruction, type ParsedTx } from '../model.js';
import { findingFor, type CustodyKey, type Detector, type DetectorContext, type Finding } from './types.js';

const ID = 'key-authority';

interface Change {
    severity: Severity;
    title: string;
    description: string;
    details: Record<string, string>;
}

/** Left out of the "Bundled with" list. */
const ROUTINE_PROGRAMS = new Set(['ComputeBudget111111111111111111111111111111']);

export const keyAuthority: Detector = {
    id: ID,
    description:
        'Stake authority, token owner, delegate and account-owner changes signed by treasuries and watched keys, or made to their token accounts',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const changes: [ParsedInstruction, CustodyKey, Change][] = [];
        for (const ix of tx.instructions) {
            const key =
                signers(ix)
                    .map((s) => ctx.targets.custodyKeys.get(s))
                    .find(Boolean) ?? treasuryOfTokenAccount(ix, ctx);
            const change = key ? describe(ix, key, ctx) : null;
            if (key && change) changes.push([ix, key, change]);
        }
        if (changes.length === 0) return [];

        const handled = new Set(changes.map(([ix]) => ix));
        const others = tx.instructions
            .filter((ix) => ix.innerInstructionIndex === null && !handled.has(ix) && !ROUTINE_PROGRAMS.has(ix.programId))
            .map((ix) => ix.instructionName ?? ix.programId);
        return changes.map(([ix, key, change]) =>
            findingFor(ID, tx, ix, {
                severity: change.severity,
                title: change.title,
                description: `${change.description}${changes.length > 1 ? ` This transaction makes ${changes.length} such changes.` : ''}`,
                subject: key.subject,
                subjectLabel: key.subjectLabel,
                details: {
                    ...change.details,
                    'Signed by': `${key.label} ${key.address}`,
                    ...(others.length > 0 ? { 'Bundled with': others.join(', ') } : {}),
                },
                stages: ['control'],
            }),
        );
    },
};

/** The treasury or vault whose token account an `approve` or `set_authority` changes, whoever signed it. */
function treasuryOfTokenAccount(ix: ParsedInstruction, ctx: DetectorContext): CustodyKey | undefined {
    if (ix.programId !== PROGRAMS.splToken && ix.programId !== PROGRAMS.token2022) return undefined;
    const name = nameOf(ix);
    const target =
        name === 'setauthority'
            ? account(ix, 'mint_or_account')
            : name === 'approve' || name === 'approvechecked'
              ? sourceOf(ix)
              : undefined;
    if (!target) return undefined;
    for (const treasury of ctx.targets.treasuries.values()) {
        if (treasury.tokenAccounts.has(target.pubkey)) {
            return { address: treasury.address, label: treasury.label, subject: treasury.address, subjectLabel: treasury.label };
        }
    }
    return undefined;
}

function sourceOf(ix: ParsedInstruction) {
    return account(ix, 'source_account') ?? account(ix, 'source');
}

function describe(ix: ParsedInstruction, key: CustodyKey, ctx: DetectorContext): Change | null {
    const name = nameOf(ix);
    if (!name) return null;
    if (ix.programId === PROGRAMS.stake) return stakeChange(ix, name, key);
    if (ix.programId === PROGRAMS.splToken || ix.programId === PROGRAMS.token2022) return tokenChange(ix, name, key, ctx);
    if (ix.programId === PROGRAMS.system && (name === 'assign' || name === 'assignwithseed')) {
        const owner = pubkeyArg(ix, 'owner') ?? pubkeyArg(ix, 'programId') ?? 'unknown';
        const target = account(ix, 'account')?.pubkey ?? account(ix, 'assigned_account')?.pubkey ?? key.address;
        return {
            severity: 'critical',
            title: 'Account reassigned to a program',
            description: `${key.label} signed a System assign that hands ${target} to program ${owner}, which then controls its funds. This is the "owner change" phishing pattern.`,
            details: { Account: target, 'New owner program': owner },
        };
    }
    return null;
}

function stakeChange(ix: ParsedInstruction, name: string, key: CustodyKey): Change | null {
    const stakeAccount = account(ix, 'stake_account')?.pubkey ?? 'unknown';
    if (name.startsWith('authorize')) {
        const newAuthority = pubkeyArg(ix, 'newAuthorizedPubkey') ?? account(ix, 'new_authority')?.pubkey ?? 'unknown';
        const role = String(arg(ix, 'stakeAuthorize') ?? 'unknown');
        if (newAuthority === key.address) return null;
        const withdrawer = normalizeName(role) === 'withdrawer';
        return {
            severity: withdrawer ? 'critical' : 'high',
            title: `Stake ${role.toLowerCase()} authority moved`,
            description: `${key.label} gave the ${role.toLowerCase()} authority of stake account ${stakeAccount} to ${newAuthority}.${withdrawer ? ' The withdrawer can take the whole balance.' : ''}`,
            details: { 'Stake account': stakeAccount, 'New authority': newAuthority, Authority: role },
        };
    }
    if (name.startsWith('setlockup')) {
        return {
            severity: 'high',
            title: 'Stake lockup changed',
            description: `${key.label} changed the lockup of stake account ${stakeAccount}, which can block withdrawals or change the custodian.`,
            details: { 'Stake account': stakeAccount },
        };
    }
    return null;
}

function tokenChange(ix: ParsedInstruction, name: string, key: CustodyKey, ctx: DetectorContext): Change | null {
    if (name === 'setauthority') {
        const target = account(ix, 'mint_or_account')?.pubkey ?? 'unknown';
        if (ctx.targets.mints.has(target)) return null;
        const authorityType = String(arg(ix, 'authorityType') ?? 'unknown');
        const newAuthority = pubkeyArg(ix, 'newAuthority');
        const ownership = normalizeName(authorityType) === 'accountowner';
        return {
            severity: ownership ? 'critical' : 'high',
            title: ownership ? 'Token account ownership transferred' : `Token account ${authorityType} authority changed`,
            description: `${key.label} ${newAuthority ? `gave the ${authorityType} authority of token account ${target} to ${newAuthority}` : `removed the ${authorityType} authority of ${target}`}.`,
            details: { 'Token account': target, 'New authority': newAuthority ?? 'none', 'Authority type': authorityType },
        };
    }
    if (name === 'approve' || name === 'approvechecked') {
        const delegate = account(ix, 'delegate')?.pubkey ?? 'unknown';
        const source = sourceOf(ix)?.pubkey ?? 'unknown';
        const amount = arg(ix, 'amount');
        return {
            severity: 'high',
            title: 'Token delegate approved',
            description: `${key.label} let ${delegate} spend up to ${String(amount ?? 'an unknown amount')} raw units from ${source} without another signature.`,
            details: { Delegate: delegate, 'Token account': source, Amount: String(amount ?? 'unknown') },
        };
    }
    return null;
}
