import { describe, expect, it } from 'vitest';
import type { BackfillResult } from '../src/backfill.js';
import { parseConfig } from '../src/config.js';
import { assessPosture } from '../src/report/posture.js';
import { renderHtml, type ReportData } from '../src/report/render.js';

const config = {
    ...parseConfig({ programs: [{ id: 'KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD' }] }),
    apiKey: 'k',
    endpoints: {},
    configPath: '',
};
const report = (coverage: BackfillResult[], coverageNote?: string): ReportData => ({
    generatedAt: new Date('2026-11-03T00:00:00Z'),
    lookbackDays: 7,
    posture: assessPosture(config, { programs: [], mints: [], multisigs: [], seizable: [] }, { currentSlot: 1, slotMs: 400 }),
    findings: [],
    coverage,
    ...(coverageNote ? { coverageNote } : {}),
});

describe('HTML report coverage', () => {
    it('explains an empty coverage table', () => {
        expect(renderHtml(report([], 'History scans are still running. Reload this page in a moment.'))).toContain(
            '<td colspan="6" class="muted">History scans are still running. Reload this page in a moment.</td>',
        );
        expect(renderHtml(report([]))).toContain('No history scans ran for this report.');
    });

    it('lists each scan', () => {
        const scan = {
            plan: {
                key: 'k',
                label: 'Kamino Lend deployments',
                address: 'PData',
                match: { programs: [] },
                status: 'succeeded',
                detectors: [],
                subject: 's',
            },
            progress: { windowEnded: true, scannedTransactions: 1_234, matchedTransactions: 2, creditsCharged: 11 },
            coverage: 'complete',
            summary: { label: 'Up to date', detail: '' },
            findings: 0,
        } as unknown as BackfillResult;
        const html = renderHtml(report([scan]));
        expect(html).toContain('Kamino Lend deployments');
        expect(html).toContain('1,234');
        expect(html).not.toContain('No history scans');
    });
});
