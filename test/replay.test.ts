import { describe, expect, it } from 'vitest';
import { detectorCoverage, type DetectorCoverage, type PlanScan } from '../src/commands/replay.js';
import { parseConfig, type Config } from '../src/config.js';
import { scanPlans, type ScanPlan } from '../src/targets.js';
import { context, KEYS } from './helpers.js';

function testConfig(privilegedInstructions: string[]): Config {
    return { ...parseConfig({ programs: [{ id: KEYS.program, privilegedInstructions }] }), apiKey: 'k', endpoints: {}, configPath: '' };
}

function replay(options: { privileged?: string[]; adminKeys?: string[]; outcome?: (plan: ScanPlan) => PlanScan['outcome'] } = {}) {
    const { targets } = context();
    targets.programs.get(KEYS.program)!.adminKeys = options.adminKeys ?? [];
    const config = testConfig(options.privileged ?? ['set_admin']);
    const scans = scanPlans(config, targets).map((plan): PlanScan => ({ plan, outcome: options.outcome?.(plan) ?? 'complete' }));
    const coverage = detectorCoverage(scans, config, targets, 0);
    return { coverage, of: (detector: string) => coverage.find((c) => c.detector === detector) as DetectorCoverage };
}

describe('replay detector coverage', () => {
    it('marks every scanned detector as ran when each scan reached the window end', () => {
        const { coverage } = replay();
        expect(Object.fromEntries(coverage.map((c) => [c.detector, c.status]))).toEqual({
            'program-deployment': 'ran',
            'upgrade-proposal': 'ran',
            'multisig-proposal': 'ran',
            'multisig-change': 'ran',
            'mint-authority': 'ran',
            'permanent-delegate': 'nothing-to-watch',
            'privileged-instruction': 'ran',
            'admin-key-behavior': 'nothing-to-watch',
            'treasury-outflow': 'ran',
            'nonce-authority': 'live-only',
            'key-authority': 'ran',
            'idl-change': 'ran',
            'config-change': 'live-only',
            'build-verification': 'live-only',
            'attack-chain': 'ran',
        });
    });

    it('says what --no-program-scans left out, and carries the gap into attack-chain', () => {
        const { of } = replay({
            adminKeys: [KEYS.member],
            outcome: (plan) => (plan.address === KEYS.program ? 'skipped' : 'complete'),
        });
        expect(of('privileged-instruction').status).toBe('missing-data');
        expect(of('privileged-instruction').reason).toContain('Skipped by --no-program-scans: Test Program admin instructions');
        expect(of('attack-chain')).toMatchObject({ status: 'missing-data' });
        expect(of('attack-chain').reason).toContain('privileged-instruction missed data');
    });

    it('names the scans that stopped at the budget', () => {
        const { of } = replay({ outcome: (plan) => (plan.detectors.includes('treasury-outflow') ? 'budget' : 'complete') });
        expect(of('treasury-outflow')).toEqual({
            detector: 'treasury-outflow',
            status: 'missing-data',
            reason: 'Stopped at --budget before the window end: Treasury outflows.',
        });
    });

    it('reports a program without known admin instructions as missing data, not nothing to watch', () => {
        const { of } = replay({ privileged: [] });
        expect(of('privileged-instruction')).toMatchObject({ status: 'missing-data' });
        expect(of('privileged-instruction').reason).toContain('No admin instructions are known for Test Program');
    });

    it('reports detectors without targets as nothing to watch', () => {
        const { targets } = context();
        targets.mints.clear();
        targets.treasuries.clear();
        const config = testConfig(['set_admin']);
        const scans = scanPlans(config, targets).map((plan): PlanScan => ({ plan, outcome: 'complete' }));
        const coverage = detectorCoverage(scans, config, targets, 0);
        expect(coverage.find((c) => c.detector === 'mint-authority')).toMatchObject({ status: 'nothing-to-watch' });
        expect(coverage.find((c) => c.detector === 'treasury-outflow')!.reason).toContain("discovered from today's balances");
    });
});
