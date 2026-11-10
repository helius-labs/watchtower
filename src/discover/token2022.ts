import { getAddressDecoder } from '@solana/kit';
import { severityRank, type Severity } from '../config.js';

export interface MintControl {
    extension: string;
    severity: Severity;
    text: string;
}

/** Token-2022 mints carry TLV extensions after the 165-byte base and the account-type byte. */
const EXTENSIONS_OFFSET = 166;
const ZERO_KEY = '11111111111111111111111111111111';
const FROZEN_ACCOUNT_STATE = 2;
const PERMANENT_DELEGATE = 12;

/** Keyed by spl-token-2022 `ExtensionType`; each reader gets the extension's TLV value. */
const READERS = new Map<number, (value: Uint8Array) => MintControl | null>([
    [
        PERMANENT_DELEGATE,
        (v) =>
            keyed(v, 0, (delegate) => ({
                extension: 'Permanent delegate',
                severity: 'critical',
                text: `${delegate} can transfer or burn tokens from any holder`,
            })),
    ],
    [
        14,
        (v) =>
            keyed(v, 32, (program) => ({
                extension: 'Transfer hook',
                severity: 'critical',
                text: `every transfer runs program ${program}, which can block or change transfers`,
            })),
    ],
    [
        9,
        () => ({
            extension: 'Non-transferable',
            severity: 'critical',
            text: 'tokens cannot be transferred, so collateral cannot be liquidated',
        }),
    ],
    [
        26,
        (v) =>
            keyed(v, 0, (authority) => ({
                extension: 'Pausable',
                severity: 'high',
                text: `${authority} can pause all transfers${v[32] === 1 ? ', and transfers are paused now' : ''}`,
            })),
    ],
    [
        6,
        (v) =>
            v[0] === FROZEN_ACCOUNT_STATE
                ? { extension: 'Default account state', severity: 'high', text: 'new token accounts start frozen' }
                : null,
    ],
    [
        1,
        (v) => {
            const bps = new DataView(v.buffer, v.byteOffset, v.byteLength).getUint16(106, true);
            return bps > 0
                ? { extension: 'Transfer fee', severity: 'medium', text: `${bps / 100}% of every transfer is withheld as a fee` }
                : null;
        },
    ],
    [
        3,
        (v) =>
            keyed(v, 0, (authority) => ({
                extension: 'Mint close authority',
                severity: 'medium',
                text: `${authority} can close the mint once supply is zero`,
            })),
    ],
    [
        10,
        () => ({
            extension: 'Interest-bearing',
            severity: 'medium',
            text: 'the displayed balance grows with an interest rate the rate authority sets',
        }),
    ],
    [
        25,
        () => ({
            extension: 'Scaled UI amount',
            severity: 'medium',
            text: 'the displayed balance is multiplied by a factor the authority can change',
        }),
    ],
]);

/** Risky extensions in Token-2022 mint data, most severe first. */
export function mintControls(data: Uint8Array): MintControl[] {
    const controls: MintControl[] = [];
    for (const [type, value] of extensions(data)) {
        const control = READERS.get(type)?.(value);
        if (control) controls.push(control);
    }
    return controls.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

/** The key that can transfer or burn any holder's tokens, from Token-2022 mint data. */
export function permanentDelegateOf(data: Uint8Array): string | null {
    for (const [type, value] of extensions(data)) {
        if (type !== PERMANENT_DELEGATE || value.length < 32) continue;
        const key = getAddressDecoder().decode(value.subarray(0, 32));
        return key === ZERO_KEY ? null : key;
    }
    return null;
}

function* extensions(data: Uint8Array): Generator<[type: number, value: Uint8Array]> {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    for (let offset = EXTENSIONS_OFFSET; offset + 4 <= data.length;) {
        const type = view.getUint16(offset, true);
        const length = view.getUint16(offset + 2, true);
        if (type === 0) return;
        yield [type, data.subarray(offset + 4, offset + 4 + length)];
        offset += 4 + length;
    }
}

/** An optional public key at `offset`; all zeros means unset. */
function keyed(value: Uint8Array, offset: number, control: (key: string) => MintControl): MintControl | null {
    if (value.length < offset + 32) return null;
    const key = getAddressDecoder().decode(value.subarray(offset, offset + 32));
    return key === ZERO_KEY ? null : control(key);
}
