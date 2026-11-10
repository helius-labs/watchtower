import type { Config } from '../config.js';
import type { PrivilegedKey, SeizableAccount } from '../detectors/types.js';
import type { BuildCheck } from '../discover/build.js';
import type { MintState, ProgramState } from '../discover/index.js';
import { votingMembers, type SquadsMultisig } from '../discover/squads.js';
import { humanDuration, short } from '../format.js';
import type { Discovery } from '../targets.js';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface PostureCheck {
    status: CheckStatus;
    title: string;
    detail: string;
    fix?: string;
    /** Points this check takes off its subject's score. */
    penalty: number;
}

type CheckResult = Omit<PostureCheck, 'penalty'>;

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface SubjectPosture {
    kind: 'program' | 'multisig' | 'mint';
    address: string;
    label: string;
    score: number;
    grade: Grade;
    checks: PostureCheck[];
}

/** The overall score is the weakest subject's. */
export interface Posture {
    score: number;
    grade: Grade;
    subjects: SubjectPosture[];
    /** Which subject sets the score, in words. */
    basis: string;
    /** How scores and grades are calculated, in words. */
    rubric: string[];
}

const RUBRIC = {
    penalties: { fail: 25, warn: 10, pass: 0, info: 0 } satisfies Record<CheckStatus, number>,
    grades: [
        ['A', 90],
        ['B', 75],
        ['C', 60],
        ['D', 40],
        ['F', 0],
    ] satisfies [Grade, number][],
};

export interface ChainClock {
    currentSlot: number;
    slotMs: number;
}

/** Existing nonce accounts per privileged key, or why they could not be listed. */
export type NonceExposure = { keys: PrivilegedKey[]; accounts: Map<string, string[]> } | { error: string };

export function assessPosture(config: Config, discovery: Discovery, chain: ChainClock, nonces?: NonceExposure): Posture {
    const subjects: SubjectPosture[] = [
        ...discovery.programs.map((program) => {
            const configured = config.programs.find((p) => p.id === program.programId);
            const governedBy = [program.programId, ...(program.multisig ? [program.multisig.address] : [])];
            return subject('program', program.programId, configured?.name ?? short(program.programId), [
                ...programChecks(program, configured?.privilegedInstructions ?? [], chain),
                ...seizableChecks(
                    discovery.seizable,
                    program.vaults.map((v) => v.authority),
                ),
                ...nonceChecks(nonces, governedBy),
            ]);
        }),
        ...discovery.multisigs.map((multisig) =>
            subject(
                'multisig',
                multisig.address,
                config.multisigs.find((m) => m.address === multisig.address)?.label ?? short(multisig.address),
                [
                    ...multisigChecks(multisig, `Squads v${multisig.version} multisig ${multisig.address}`, 'Transactions'),
                    ...nonceChecks(nonces, [multisig.address]),
                ],
            ),
        ),
        ...discovery.mints.map((mint) =>
            subject('mint', mint.address, config.mints.find((m) => m.address === mint.address)?.label ?? short(mint.address), [
                ...mintChecks(mint),
                ...nonceChecks(nonces, [mint.address]),
            ]),
        ),
    ];
    const score = Math.min(100, ...subjects.map((s) => s.score));
    return { score, grade: gradeFor(score), subjects, basis: basisFor(subjects), rubric: describeRubric() };
}

function subject(kind: SubjectPosture['kind'], address: string, label: string, results: CheckResult[]): SubjectPosture {
    const checks = results.map((check) => ({ ...check, penalty: RUBRIC.penalties[check.status] }));
    const score = Math.max(0, 100 - checks.reduce((sum, check) => sum + check.penalty, 0));
    return { kind, address, label, score, grade: gradeFor(score), checks };
}

function programChecks(program: ProgramState, privileged: string[], chain: ChainClock): CheckResult[] {
    const checks: CheckResult[] = [];
    switch (program.authorityKind) {
        case 'immutable':
            checks.push({ status: 'pass', title: 'Program is immutable', detail: 'No key can change the deployed code.' });
            break;
        case 'wallet':
            checks.push({
                status: 'fail',
                title: 'Upgrade authority is a single wallet',
                detail: `${program.upgradeAuthority} can replace the program's code at any time with one signature.`,
                fix: 'Transfer the upgrade authority to a Squads multisig vault with a time lock, or make the program immutable if it no longer needs upgrades.',
            });
            break;
        case 'unknown-pda':
            checks.push({
                status: 'warn',
                title: 'Upgrade authority is an unrecognized PDA',
                detail: `${program.upgradeAuthority} is a program-derived address, but not a Squads vault. It may be governance or a custom program.`,
                fix: 'Confirm who controls this address. Watchtower can grade the threshold and time lock only when the authority is a Squads vault.',
            });
            break;
        case 'squads': {
            const multisig = program.multisig!;
            const pda = `${multisig.version === 4 ? 'vault' : 'authority'} ${multisig.vaultIndex}`;
            checks.push(...multisigChecks(multisig, `Squads v${multisig.version} multisig ${multisig.address} (${pda})`, 'Upgrades'));
            break;
        }
    }

    checks.push(...adminChecks(program, privileged));
    if (program.build) checks.push(buildCheck(program.build));

    const slotsAgo = chain.currentSlot - program.lastDeploySlot;
    checks.push({
        status: 'info',
        title: 'Last deployment',
        detail: `Slot ${program.lastDeploySlot.toLocaleString('en-US')}, about ${humanDuration((slotsAgo * chain.slotMs) / 1000)} ago.`,
    });

    const suggested = program.idl?.privileged ?? [];
    if (privileged.length === 0 && suggested.length > 0) {
        const one = suggested.length === 1;
        checks.push({
            status: 'warn',
            title: 'Admin instructions are not monitored',
            detail: `The IDL has ${suggested.length} instruction${one ? '' : 's'} that look${one ? 's' : ''} admin-only (${suggested.slice(0, 6).join(', ')}${suggested.length > 6 ? ', …' : ''}), but none are watched.`,
            fix: 'Pick the admin-only instructions in Setup → Programs, or list them under privilegedInstructions in watchtower.yaml.',
        });
    } else if (!program.idl) {
        checks.push({
            status: 'info',
            title: 'No IDL published',
            detail: 'Parsed Events has no IDL for this program, so its own instructions cannot be decoded. Publish an Anchor or Program Metadata IDL to monitor admin instructions.',
        });
    }
    return checks;
}

function adminChecks(program: ProgramState, privileged: string[]): CheckResult[] {
    if (privileged.length === 0) return [];
    if (program.admins.length === 0) {
        return [
            {
                status: 'info',
                title: 'No admin signer seen yet',
                detail: 'No recent admin call was signed in an admin role, so the admin key could not be graded.',
            },
        ];
    }
    return program.admins.flatMap((admin): CheckResult[] => {
        const who = `Admin key ${admin.key} (${admin.role})`;
        if (admin.multisig && admin.multisig.address === program.multisig?.address) {
            return [
                {
                    status: 'pass',
                    title: 'Admin is the upgrade multisig',
                    detail: `${who} is a vault of the same multisig that controls upgrades.`,
                },
            ];
        }
        switch (admin.kind) {
            case 'wallet':
                return [
                    {
                        status: 'fail',
                        title: 'Admin key is a single wallet',
                        detail: `${who} can change protocol settings, list assets or move admin control with one signature.`,
                        fix: 'Move admin control to a Squads multisig with a time lock.',
                    },
                ];
            case 'unknown-pda':
                return [
                    {
                        status: 'warn',
                        title: 'Admin key is an unrecognized PDA',
                        detail: `${who} is a program-derived address, but not a Squads vault.`,
                        fix: 'Confirm who controls this address. Watchtower can grade it only when it is a Squads vault.',
                    },
                ];
            case 'squads': {
                const multisig = admin.multisig!;
                return multisigChecks(multisig, `${who}: Squads v${multisig.version} multisig ${multisig.address}`, 'Admin actions');
            }
        }
    });
}

function buildCheck(build: BuildCheck): CheckResult {
    if (build.verified) {
        return {
            status: 'pass',
            title: 'Deployed bytecode is a verified build',
            detail: `It matches ${build.source}, verified by OtterSec.`,
        };
    }
    return build.source
        ? {
              status: 'warn',
              title: 'Deployed bytecode does not match its verified build',
              detail: `The program registered ${build.source} for verification, but the bytecode on-chain (hash ${build.hash.slice(0, 12)}…) is not that build.`,
              fix: 'Re-run solana-verify for the deployed commit, or find out what was deployed instead.',
          }
        : {
              status: 'warn',
              title: 'No verified build',
              detail: 'Nobody can confirm which source code the deployed bytecode was built from.',
              fix: 'Publish a verified build with solana-verify so users and monitors can match the bytecode to source.',
          };
}

function multisigChecks(multisig: SquadsMultisig, where: string, actions: string): CheckResult[] {
    const voters = votingMembers(multisig);
    const checks: CheckResult[] = [];
    const raiseThreshold = `Raise the threshold to at least ${Math.ceil(voters / 2)} of ${voters}.`;

    if (multisig.threshold <= 1) {
        checks.push({
            status: 'fail',
            title: `${actions} need only 1 of ${voters} signatures`,
            detail: `${where}: any single member can act alone.`,
            fix: raiseThreshold,
        });
    } else if (multisig.threshold < Math.ceil(voters / 2)) {
        checks.push({
            status: 'warn',
            title: `${actions} need ${multisig.threshold} of ${voters} signatures`,
            detail: `${where}: the threshold is below half of the voting members.`,
            fix: raiseThreshold,
        });
    } else {
        checks.push({
            status: 'pass',
            title: `${actions} need ${multisig.threshold} of ${voters} signatures`,
            detail: `${where}.`,
        });
    }

    checks.push(
        multisig.timeLockSeconds === 0
            ? {
                  status: 'warn',
                  title: 'No time lock',
                  detail:
                      multisig.version === 3
                          ? 'Squads v3 does not support time locks, so an approved transaction executes immediately.'
                          : 'An approved transaction can execute immediately, leaving users no time to react.',
                  fix:
                      multisig.version === 3
                          ? 'Migrate to Squads v4 and set a time lock; 24 hours is common.'
                          : 'Set a time lock on the multisig; 24 hours is common.',
              }
            : {
                  status: 'pass',
                  title: `Time lock of ${humanDuration(multisig.timeLockSeconds)}`,
                  detail: 'Approved transactions wait before they can execute.',
              },
    );

    if (multisig.configAuthority) {
        checks.push({
            status: 'warn',
            title: 'Controlled multisig',
            detail: `Config authority ${multisig.configAuthority} can add or remove members and change the threshold without a vote.`,
            fix: 'Remove the config authority so membership and threshold changes need a vote.',
        });
    }
    return checks;
}

function nonceChecks(nonces: NonceExposure | undefined, subjects: string[]): CheckResult[] {
    if (!nonces) return [];
    if ('error' in nonces) return [{ status: 'info', title: 'Nonce accounts not checked', detail: nonces.error }];
    const keys = nonces.keys.filter((k) => subjects.includes(k.subject) && nonces.accounts.has(k.address));
    if (keys.length === 0) return [];
    const exposed = keys.filter((k) => (nonces.accounts.get(k.address) ?? []).length > 0);
    if (exposed.length === 0) {
        return [
            {
                status: 'pass',
                title: 'No durable nonce accounts in use',
                detail: `None of its ${keys.length} privileged keys has used a nonce account it still controls.`,
            },
        ];
    }
    return [
        {
            status: 'warn',
            title: `${exposed.length} privileged key${exposed.length === 1 ? '' : 's'} control durable nonce accounts`,
            detail: `${exposed.map((k) => `${k.role} ${k.address}: ${nonces.accounts.get(k.address)!.join(', ')}`).join('; ')}. Signatures against a durable nonce never expire.`,
            fix: 'Close nonce accounts that are no longer needed by withdrawing their full balance.',
        },
    ];
}

function seizableChecks(seizable: SeizableAccount[], vaults: string[]): CheckResult[] {
    const held = seizable.filter((a) => vaults.includes(a.owner));
    if (held.length === 0) return [];
    return [
        {
            status: 'info',
            title: 'Vaults hold tokens a permanent delegate can take',
            detail: `${held.map((a) => `${short(a.delegate)} can move or burn ${short(a.mint)} from ${short(a.owner)}`).join('; ')}. Watchtower alerts when it does.`,
        },
    ];
}

function mintChecks(mint: MintState): CheckResult[] {
    return [
        mint.mintAuthority
            ? {
                  status: 'warn',
                  title: 'Mint authority is active',
                  detail: `${mint.mintAuthority} can mint new supply.`,
                  fix: 'Revoke the mint authority if supply is meant to be fixed; otherwise move it to a multisig.',
              }
            : { status: 'pass', title: 'Fixed supply', detail: 'The mint authority has been revoked.' },
        mint.freezeAuthority
            ? {
                  status: 'warn',
                  title: 'Freeze authority is active',
                  detail: `${mint.freezeAuthority} can freeze any holder's token account.`,
                  fix: 'Revoke the freeze authority unless you need it, for example for compliance; otherwise move it to a multisig.',
              }
            : { status: 'pass', title: 'No freeze authority', detail: 'Token accounts cannot be frozen.' },
        ...mint.controls.map((control): CheckResult => ({
            status: control.severity === 'critical' ? 'fail' : 'warn',
            title: `Token-2022 ${control.extension.toLowerCase()}`,
            detail: `${control.text[0]!.toUpperCase()}${control.text.slice(1)}.`,
            fix: 'Remove the extension or revoke its authority if holders do not need it; otherwise put the authority behind a multisig with a time lock and document why it exists.',
        })),
    ];
}

function describeRubric(): string[] {
    const { penalties, grades } = RUBRIC;
    let above = 0;
    const bands = grades.map(([grade, min]) => {
        const band = above === 0 ? `${grade} ${min}+` : min === 0 ? `${grade} below ${above}` : `${grade} ${min}–${above - 1}`;
        above = min;
        return band;
    });
    return [
        `Each program, multisig and mint starts at 100. A failed check costs ${penalties.fail} points and a warning costs ${penalties.warn}; passes and notes cost nothing.`,
        'The overall score is the lowest subject score, because one weak link is enough for an attacker.',
        `Grades: ${bands.join(', ')}.`,
    ];
}

function basisFor(subjects: SubjectPosture[]): string {
    const weakest = subjects.reduce<SubjectPosture | undefined>((low, s) => (!low || s.score < low.score ? s : low), undefined);
    if (!weakest) return 'Nothing graded yet.';
    const n = subjects.length;
    return n === 1 ? `The score of ${weakest.label}.` : `Set by ${weakest.label}, the lowest of ${n} subjects.`;
}

function gradeFor(score: number): Grade {
    return RUBRIC.grades.find(([, min]) => score >= min)![0];
}
