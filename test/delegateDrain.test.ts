import { describe, expect, it } from 'vitest';
import { parseConfig, type Config } from '../src/config.js';
import { PROGRAMS } from '../src/constants.js';
import { detect } from '../src/detectors/index.js';
import type { TokenTransfer } from '../src/model.js';
import { assessPosture } from '../src/report/posture.js';
import { buildTargets, scanPlans, subscriptions } from '../src/targets.js';
import { context, KEYS, tx } from './helpers.js';

const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const TOKEN_ACCOUNT = 'TreasuryUsdc1111111111111111111111111111111';
const DELEGATE = 'De1egate11111111111111111111111111111111111';

/** As Parsed Events reports it: `fromUserAccount` is whoever signed, not the source account's owner. */
function usdcOut(signer: string, amount: number): TokenTransfer {
    return {
        fromUserAccount: signer,
        toUserAccount: KEYS.attacker,
        fromTokenAccount: TOKEN_ACCOUNT,
        toTokenAccount: 'AttackerUsdc1111111111111111111111111111111',
        rawTokenAmount: amount * 1_000_000,
        decimals: 6,
        tokenStandard: 'Fungible',
        mint: USDC,
    } as TokenTransfer;
}

const transfer = (signer: string, amount: number) =>
    tx(`out-${signer}-${amount}`, 10, [{ programId: PROGRAMS.splToken, name: 'transfer_checked' }], {
        tokenTransfers: [usdcOut(signer, amount)],
    });

describe('treasury-outflow: delegate-signed transfers', () => {
    it("counts a delegate's transfer out of a treasury token account, and says who signed it", () => {
        const ctx = context({ thresholds: { [USDC]: 50_000 }, treasuryTokenAccounts: [TOKEN_ACCOUNT] });
        const findings = detect(transfer(DELEGATE, 80_000), ctx).filter((f) => f.detector === 'treasury-outflow');
        expect(findings.map((f) => [f.severity, f.title])).toEqual([
            ['high', 'Outflow signed by a delegate'],
            ['high', 'Large treasury outflow'],
        ]);
        expect(findings[0]).toMatchObject({
            stages: ['drain'],
            details: { Delegate: DELEGATE, 'Token account': TOKEN_ACCOUNT, Amount: `80,000 ${USDC.slice(0, 4)}…${USDC.slice(-4)}` },
        });
    });

    it("missed it without the treasury's token accounts, and doesn't call the owner a delegate", () => {
        const blind = context({ thresholds: { [USDC]: 50_000 } });
        expect(detect(transfer(DELEGATE, 80_000), blind).filter((f) => f.detector === 'treasury-outflow')).toEqual([]);

        const ctx = context({ thresholds: { [USDC]: 50_000 }, treasuryTokenAccounts: [TOKEN_ACCOUNT] });
        const owner = detect(transfer(KEYS.treasury, 80_000), ctx).filter((f) => f.detector === 'treasury-outflow');
        expect(owner.map((f) => f.title)).toEqual(['Large treasury outflow']);
    });

    it("alerts on a delegate approved on a vault's token account by CPI, which no custody key signs", () => {
        const ctx = context({ treasuryTokenAccounts: [TOKEN_ACCOUNT] });
        ctx.targets.custodyKeys.clear();
        const approve = tx('approve', 10, [
            {
                programId: KEYS.program,
                name: 'grant',
                inner: [
                    {
                        programId: PROGRAMS.splToken,
                        name: 'approve',
                        accounts: [
                            ['source_account', TOKEN_ACCOUNT],
                            ['delegate', DELEGATE],
                            ['owner', KEYS.treasury, true],
                        ],
                        args: { amount: '1000000000' },
                    },
                ],
            },
        ]);
        expect(detect(approve, ctx).map((f) => [f.detector, f.severity, f.title, f.subject])).toEqual([
            ['key-authority', 'high', 'Token delegate approved', KEYS.treasury],
        ]);
    });

    it("scans every treasury token account through the owner's plan, and streams delegated ones", () => {
        const config = {
            ...parseConfig({ programs: [{ id: KEYS.program }], treasuries: [{ address: KEYS.treasury, label: 'Ops' }] }),
            apiKey: 'k',
            endpoints: {},
            configPath: '',
        } satisfies Config;
        const tokenAccounts = [
            { address: TOKEN_ACCOUNT, owner: KEYS.treasury, mint: USDC, delegate: DELEGATE, permanentDelegate: null },
            { address: KEYS.buffer, owner: KEYS.treasury, mint: KEYS.mint, delegate: null, permanentDelegate: null },
        ];
        const targets = buildTargets(config, { programs: [], mints: [], multisigs: [], tokenAccounts }, undefined, 400);
        expect(targets.treasuries.get(KEYS.treasury)).toMatchObject({
            tokenAccounts: new Set([TOKEN_ACCOUNT, KEYS.buffer]),
            delegates: new Map([[TOKEN_ACCOUNT, DELEGATE]]),
        });
        const treasuryPlans = scanPlans(config, targets).filter((p) => p.detectors.includes('treasury-outflow'));
        expect(treasuryPlans.map((p) => [p.address, p.tokenAccounts])).toEqual([[KEYS.treasury, 'balanceChanged']]);
        expect(subscriptions(config, targets).find((s) => s.label === 'treasuries')?.filter.accounts?.include).toEqual([
            KEYS.treasury,
            TOKEN_ACCOUNT,
        ]);
    });

    it("notes a vault's delegated token accounts in posture", () => {
        const config = {
            ...parseConfig({ programs: [{ id: KEYS.program }] }),
            apiKey: 'k',
            endpoints: {},
            configPath: '',
        } satisfies Config;
        const program = {
            programId: KEYS.program,
            programData: KEYS.programData,
            upgradeAuthority: null,
            authorityKind: 'immutable' as const,
            lastDeploySlot: 1,
            multisig: null,
            idl: null,
            admins: [],
            vaults: [{ authority: KEYS.vault, usd: 1_000_000, holdings: [] }],
            configAccounts: [],
            unlocatedConfigs: [],
            build: null,
        };
        const tokenAccounts = [{ address: TOKEN_ACCOUNT, owner: KEYS.vault, mint: USDC, delegate: DELEGATE, permanentDelegate: null }];
        const posture = assessPosture(
            config,
            { programs: [program], mints: [], multisigs: [], tokenAccounts },
            { currentSlot: 10, slotMs: 400 },
        );
        expect(posture.subjects[0]!.checks.find((c) => c.title === 'Vault token accounts have an approved delegate')).toMatchObject({
            status: 'info',
            penalty: 0,
            detail: 'De1e…1111 can move EPjF…Dt1v from Trea…1111, owned by Vau1…1111. Watchtower alerts on every transfer it signs.',
        });
    });
});
