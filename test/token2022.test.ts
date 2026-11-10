import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { mintControls, permanentDelegateOf } from '../src/discover/token2022.js';

const pyusd = JSON.parse(readFileSync(new URL('./fixtures/mint-pyusd.json', import.meta.url), 'utf8')) as { data: string };

describe('Token-2022 mint controls', () => {
    it('reads the risky extensions of a real mint (PYUSD)', () => {
        // PYUSD also carries a transfer hook and transfer fee, but with no hook program and a 0% fee.
        const controls = mintControls(Buffer.from(pyusd.data, 'base64'));
        expect(controls.map((c) => [c.extension, c.severity])).toEqual([
            ['Permanent delegate', 'critical'],
            ['Mint close authority', 'medium'],
        ]);
        expect(controls[0]!.text).toBe('2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk can transfer or burn tokens from any holder');
    });

    it('ignores unset optional keys and a base mint without extensions', () => {
        const data = new Uint8Array(166 + 4 + 32);
        data[166] = 12;
        data[168] = 32;
        expect(mintControls(data)).toEqual([]);
        expect(mintControls(new Uint8Array(82))).toEqual([]);
        expect(permanentDelegateOf(data)).toBeNull();
        expect(permanentDelegateOf(new Uint8Array(82))).toBeNull();
    });

    it("reads a real mint's permanent delegate (PYUSD)", () => {
        expect(permanentDelegateOf(Buffer.from(pyusd.data, 'base64'))).toBe('2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk');
    });
});
