import { PROGRAMS } from '../constants.js';
import { formatAmount, short, toBigInt } from '../format.js';
import { arg, nameOf, normalizeName, type ParsedInstruction, type ParsedTx } from '../model.js';
import { findingFor, type Detector, type DetectorContext, type Finding } from './types.js';

const ID = 'permanent-delegate';

/**
 * Token-2022 instructions a permanent delegate can sign, keyed by parser-v2 name, with the position of the authority
 * account. The source token account is account 0 and the mint account 1; plain `transfer` cannot use the delegate.
 */
export const DELEGATE_MOVES = new Map([
    ['transfer_checked', { discriminator: '0x0c', authority: 3, burn: false }],
    ['transfer_fee_extension.transfer_checked_with_fee', { discriminator: '0x1a01', authority: 3, burn: false }],
    ['burn', { discriminator: '0x08', authority: 2, burn: true }],
    ['burn_checked', { discriminator: '0x0f', authority: 2, burn: true }],
]);

const MOVES_BY_NORMALIZED_NAME = new Map([...DELEGATE_MOVES].map(([name, move]) => [normalizeName(name), move]));

export const permanentDelegate: Detector = {
    id: ID,
    description: "Token-2022 permanent delegates moving or burning a watched treasury's or vault's tokens, or a watched mint's",
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            if (ix.programId !== PROGRAMS.token2022) continue;
            const name = nameOf(ix);
            const move = name ? MOVES_BY_NORMALIZED_NAME.get(name) : undefined;
            const keys = ix.accounts?.map((a) => a.pubkey) ?? [];
            const [source, mint, destination] = keys;
            const authority = move ? keys[move.authority] : undefined;
            if (!move || !source || !mint || !authority) continue;
            const amount = formatAmount(toBigInt(arg(ix, 'amount')) ?? 0n, decimalsOf(ix, ctx, mint));
            const details = {
                Mint: mint,
                'Token account': source,
                'Permanent delegate': authority,
                Amount: amount,
                ...(move.burn || !destination ? {} : { Destination: destination }),
            };

            const seizable = ctx.targets.seizableAccounts.get(source);
            const treasury = seizable ? ctx.targets.treasuries.get(seizable.owner) : undefined;
            if (seizable && treasury && seizable.mint === mint && seizable.delegate === authority) {
                findings.push(
                    findingFor(ID, tx, ix, {
                        severity: 'critical',
                        title: `Permanent delegate ${move.burn ? 'burned' : 'took'} tokens from ${treasury.label}`,
                        description: `${authority}, the mint's permanent delegate, ${move.burn ? 'burned' : 'moved'} ${amount} ${short(mint)} ${move.burn ? 'in' : 'out of'} ${treasury.label}'s token account ${short(source)}. A permanent delegate needs no signature from the owner, so either the issuer seized them or someone else holds its key.`,
                        subject: treasury.address,
                        subjectLabel: treasury.label,
                        details,
                        stages: ['drain'],
                    }),
                );
                continue;
            }

            const watched = ctx.targets.mints.get(mint);
            if (watched?.permanentDelegate !== authority) continue;
            findings.push(
                findingFor(ID, tx, ix, {
                    severity: 'high',
                    title: `Permanent delegate ${move.burn ? 'burned' : 'moved'} ${watched.label}`,
                    description: `The permanent delegate ${authority} ${move.burn ? 'burned' : 'moved'} ${amount} ${watched.label} ${move.burn ? 'in' : 'out of'} token account ${source}. It can do this to any holder without their signature.`,
                    subject: watched.address,
                    subjectLabel: watched.label,
                    details,
                }),
            );
        }
        return findings;
    },
};

function decimalsOf(ix: ParsedInstruction, ctx: DetectorContext, mint: string): number | null {
    const decimals = Number(arg(ix, 'decimals'));
    return Number.isInteger(decimals) ? decimals : (ctx.targets.mints.get(mint)?.decimals ?? null);
}
