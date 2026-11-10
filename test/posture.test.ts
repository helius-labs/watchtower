import { describe, expect, it } from 'vitest';
import type { Config } from '../src/config.js';
import type { ProgramState } from '../src/discover/index.js';
import { assessPosture } from '../src/report/posture.js';

const config = { programs: [{ id: 'Prog1', name: 'Example', privilegedInstructions: [] }], multisigs: [], mints: [] } as unknown as Config;
const chain = { currentSlot: 1_000, slotMs: 400 };

function program(overrides: Partial<ProgramState>): ProgramState {
    return {
        programId: 'Prog1',
        programData: 'Data1',
        upgradeAuthority: 'Wallet1',
        authorityKind: 'wallet',
        lastDeploySlot: 900,
        multisig: null,
        idl: null,
        admins: [],
        vaults: [],
        build: null,
        configAccounts: [],
        unlocatedConfigs: [],
        ...overrides,
    };
}

describe('posture', () => {
    it('costs 25 per failure and 10 per warning, each with a fix', () => {
        const posture = assessPosture(
            config,
            {
                programs: [program({ idl: { instructions: [], privileged: ['set_admin'] } as never })],
                mints: [],
                multisigs: [],
                tokenAccounts: [],
            },
            chain,
        );
        const [subject] = posture.subjects;
        expect(subject!.score).toBe(65);
        expect(subject!.grade).toBe('C');
        const costed = subject!.checks.filter((c) => c.penalty > 0);
        expect(costed.map((c) => [c.status, c.penalty])).toEqual([
            ['fail', 25],
            ['warn', 10],
        ]);
        expect(costed.every((c) => c.fix)).toBe(true);
        expect(subject!.checks.filter((c) => c.status === 'info').every((c) => c.penalty === 0 && !c.fix)).toBe(true);
    });

    it('explains which subject sets the score and the rubric', () => {
        const posture = assessPosture(
            config,
            {
                programs: [program({ authorityKind: 'immutable', upgradeAuthority: null })],
                mints: [
                    {
                        address: 'Mint1',
                        tokenProgram: 'Tok',
                        mintAuthority: 'Auth',
                        freezeAuthority: null,
                        supply: 0n,
                        decimals: 6,
                        controls: [],
                        permanentDelegate: null,
                    },
                ],
                multisigs: [],
                tokenAccounts: [],
            },
            chain,
        );
        expect(posture.score).toBe(90);
        expect(posture.basis).toMatch(/lowest of 2 subjects/);
        expect(posture.rubric.join(' ')).toContain('A 90+, B 75–89, C 60–74, D 40–59, F below 40');
    });
});
