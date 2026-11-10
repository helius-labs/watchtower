import { severityRank } from '../config.js';
import { adminKeyBehavior } from './adminKeyBehavior.js';
import { decodeTransactionBuffers } from '../discover/squads.js';
import type { ParsedTx } from '../model.js';
import { linkAttackStages } from './attackChain.js';
import { keyAuthority } from './keyAuthority.js';
import { mintAuthority } from './mintAuthority.js';
import { multisigChange } from './multisigChange.js';
import { multisigProposal } from './multisigProposal.js';
import { usesDurableNonce } from './nonce.js';
import { nonceAuthority } from './nonceAuthority.js';
import { permanentDelegate } from './permanentDelegate.js';
import { privilegedInstruction } from './privilegedInstruction.js';
import { programDeployment } from './programDeployment.js';
import { escalate } from './severity.js';
import { treasuryOutflow } from './treasuryOutflow.js';
import type { Detector, DetectorContext, Finding } from './types.js';
import { upgradeProposal } from './upgradeProposal.js';

export { linkAttackStages };

const DETECTORS: Detector[] = [
    programDeployment,
    upgradeProposal,
    multisigProposal,
    multisigChange,
    mintAuthority,
    permanentDelegate,
    privilegedInstruction,
    adminKeyBehavior,
    treasuryOutflow,
    nonceAuthority,
    keyAuthority,
];

/** The per-transaction detectors, in the order they run. */
export const DETECTOR_IDS = DETECTORS.map((d) => d.id);

/** High-or-above findings from these detectors get the `control` stage when they set none. */
const CONTROL_DETECTORS = new Set([programDeployment.id, multisigChange.id, mintAuthority.id, nonceAuthority.id]);

export function detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
    const findings = runDetectors(tx, ctx);
    return [...findings, ...linkAttackStages(tx, findings, ctx)];
}

export function runDetectors(tx: ParsedTx, ctx: DetectorContext): Finding[] {
    if (tx.succeeded) decodeTransactionBuffers(tx, ctx.state);
    const findings = DETECTORS.filter((d) => tx.succeeded || d.includeFailed).flatMap((d) => d.detect(tx, ctx));
    if (findings.length > 0 && usesDurableNonce(tx)) {
        for (const finding of findings) {
            if (finding.severity === 'info' || finding.severity === 'low') continue;
            finding.severity = escalate(finding.severity);
            finding.details['Durable nonce'] =
                'Yes. This transaction could have been signed long before it landed, so its signers may not have reviewed it recently.';
        }
    }
    for (const finding of findings) {
        if (!finding.stages && CONTROL_DETECTORS.has(finding.detector) && severityRank(finding.severity) >= severityRank('high')) {
            finding.stages = ['control'];
        }
    }
    return findings;
}
