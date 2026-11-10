import { readFileSync } from 'node:fs';
import type { ParsedTransactionResult } from 'helius-sdk/parsedEvents/types';
import { describe, expect, it } from 'vitest';
import { parseConfig, type Config } from '../src/config.js';
import { PROGRAMS } from '../src/constants.js';
import { detect } from '../src/detectors/index.js';
import { fromParsedEvents } from '../src/model.js';
import { buildTargets, scanPlans, subscriptions } from '../src/targets.js';
import { context, KEYS, tx } from './helpers.js';

const seizure = fromParsedEvents(
    JSON.parse(readFileSync(new URL('./fixtures/pyusd-delegate-transfer.json', import.meta.url), 'utf8')) as ParsedTransactionResult,
)!;
const PYUSD = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo';
const DELEGATE = '2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk';
const SOURCE = 'AucmrRFD1kzozrdtxrHJJK5RRPehtNmTmCSRL6L36hYk';
const OWNER = '6fYeEngV5qSxVX6boKWMeonziQtp9cAzbt5JXDxF44ow';

function watchingVault() {
    const ctx = context();
    ctx.targets.treasuries.set(OWNER, {
        address: OWNER,
        label: 'Lending vault',
        thresholds: new Map(),
        alertOnAnyOutflow: false,
        windowSlots: 9_000,
        allowedDestinations: new Set(),
        discovered: true,
    });
    ctx.targets.seizableAccounts.set(SOURCE, { tokenAccount: SOURCE, mint: PYUSD, delegate: DELEGATE, owner: OWNER });
    return ctx;
}

describe('permanent-delegate', () => {
    it("flags a real PYUSD seizure from a watched vault's token account, which treasury-outflow cannot see", () => {
        // Parsed Events reports the signing delegate as `fromUserAccount`, so the vault's address appears nowhere.
        expect(seizure.tokenTransfers[0]?.fromUserAccount).toBe(DELEGATE);
        const findings = detect(seizure, watchingVault());
        expect(findings.map((f) => [f.detector, f.severity, f.title])).toEqual([
            ['permanent-delegate', 'critical', 'Permanent delegate took tokens from Lending vault'],
        ]);
        expect(findings[0]).toMatchObject({
            subject: OWNER,
            stages: ['drain'],
            details: { Mint: PYUSD, 'Token account': SOURCE, 'Permanent delegate': DELEGATE, Amount: '450,030.24' },
        });
        expect(findings[0]!.description).toContain("moved 450,030.24 2b1k…4GXo out of Lending vault's token account Aucm…6hYk");
    });

    it("flags the delegate of a watched mint moving a holder's tokens, escalated for its durable nonce", () => {
        const ctx = context();
        ctx.targets.mints.set(PYUSD, { address: PYUSD, label: 'PYUSD', supply: null, decimals: 6, permanentDelegate: DELEGATE });
        const [finding, ...rest] = detect(seizure, ctx);
        expect(rest).toEqual([]);
        expect(finding).toMatchObject({ detector: 'permanent-delegate', severity: 'critical', title: 'Permanent delegate moved PYUSD' });
        expect(finding!.details['Durable nonce']).toMatch(/^Yes/);
        expect(finding!.description).toContain(`moved 450,030.24 PYUSD out of token account ${SOURCE}`);
    });

    it('ignores the owner moving its own tokens, and a delegate of a mint nothing watched holds', () => {
        const ctx = watchingVault();
        const ownTransfer = tx('own', 1, [
            {
                programId: PROGRAMS.token2022,
                name: 'transfer_checked',
                accounts: [
                    ['source_account', SOURCE],
                    ['mint', PYUSD],
                    ['destination_account', KEYS.attacker],
                    ['owner_or_delegate', OWNER, true],
                ],
                args: { amount: '1000000', decimals: 6 },
            },
        ]);
        expect(detect(ownTransfer, ctx)).toEqual([]);
        expect(detect(seizure, context())).toEqual([]);
    });

    it('flags a burn by the delegate of a watched mint', () => {
        const ctx = context({ permanentDelegate: KEYS.attacker });
        const burn = tx('burn', 1, [
            {
                programId: PROGRAMS.token2022,
                name: 'burn_checked',
                accounts: [
                    ['account', KEYS.vault],
                    ['mint', KEYS.mint],
                    ['owner_or_delegate', KEYS.attacker, true],
                ],
                args: { amount: '5000000', decimals: 6 },
            },
        ]);
        expect(detect(burn, ctx).map((f) => [f.severity, f.title, f.description])).toEqual([
            [
                'high',
                'Permanent delegate burned TEST',
                `The permanent delegate ${KEYS.attacker} burned 5 TEST in token account ${KEYS.vault}. It can do this to any holder without their signature.`,
            ],
        ]);
    });

    it('scans and streams each delegate, keeping only token accounts of watched owners', () => {
        const config = {
            ...parseConfig({
                programs: [{ id: KEYS.program }],
                mints: [{ address: PYUSD, label: 'PYUSD' }],
                treasuries: [{ address: OWNER, label: 'Ops' }],
            }),
            apiKey: 'k',
            endpoints: {},
            configPath: '',
        } satisfies Config;
        const mint = {
            address: PYUSD,
            tokenProgram: PROGRAMS.token2022,
            mintAuthority: null,
            freezeAuthority: null,
            supply: 0n,
            decimals: 6,
            controls: [],
            permanentDelegate: DELEGATE,
        };
        const seizable = [
            { tokenAccount: SOURCE, mint: PYUSD, delegate: DELEGATE, owner: OWNER },
            { tokenAccount: KEYS.buffer, mint: KEYS.mint, delegate: KEYS.attacker, owner: KEYS.nonce },
        ];
        const targets = buildTargets(config, { programs: [], mints: [mint], multisigs: [], seizable }, undefined, 400);
        expect([...targets.seizableAccounts.keys()]).toEqual([SOURCE]);
        expect(targets.privilegedKeys.get(DELEGATE)?.role).toBe('Permanent delegate of PYUSD');
        expect(scanPlans(config, targets).filter((p) => p.detectors.includes('permanent-delegate'))).toEqual([
            {
                key: `delegate:${DELEGATE}`,
                label: 'Permanent delegate 2apB…YJjk',
                address: DELEGATE,
                match: {
                    programs: [{ programId: PROGRAMS.token2022, discriminators: ['0x0c', '0x1a01', '0x08', '0x0f'], scope: 'address' }],
                },
                status: 'succeeded',
                detectors: ['permanent-delegate'],
                subject: PYUSD,
            },
        ]);
        expect(subscriptions(config, targets).find((s) => s.label === 'delegates')?.filter).toEqual({
            programs: [PROGRAMS.token2022],
            instructionNames: ['transfer_checked', 'transfer_fee_extension.transfer_checked_with_fee', 'burn', 'burn_checked'],
            accounts: { include: [DELEGATE] },
        });
    });
});
