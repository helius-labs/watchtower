// Replays real exploit windows against mainnet with `watchtower replay` and checks that Watchtower raises the alerts it
// must, and, where `only` is set, no other alerts from that detector. Exits 1 listing every problem, so CI fails when
// detection regresses or the Parsed Events API changes. Needs HELIUS_API_KEY; all cases cost about 190 credits.
//   pnpm replay:check              every case
//   pnpm replay:check raydium      one case
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const CASES = [
    {
        name: 'drift',
        about: "Drift, 2026-04-01: a new admin's first transaction lists a three-week-old token and raises withdrawal limits",
        args: ['--program', 'dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH:Drift', '--from', '2026-03-20', '--to', '2026-04-02'],
        expect: [
            {
                signature: '4a5962Rdqd9pkXtk9DMQ9ZYhdGb2k9gPw71GvukJgELhxbCY5gm1c1hhKdwuGefyqJ3XMvihUTDNDn3qbXnst82X',
                detector: 'attack-chain',
                title: 'Possible attack in progress',
            },
            {
                signature: '4a5962Rdqd9pkXtk9DMQ9ZYhdGb2k9gPw71GvukJgELhxbCY5gm1c1hhKdwuGefyqJ3XMvihUTDNDn3qbXnst82X',
                detector: 'privileged-instruction',
                title: 'Admin call from a new wallet: New market or asset added: initialize_spot_market',
            },
        ],
    },
    {
        name: 'raydium',
        about: "Raydium AMM v4, 2022-12-16: the stolen owner key's first transaction, two hours before the listed drain",
        args: ['--config', 'scripts/replays/raydium.yaml', '--from', '2022-11-15', '--to', '2022-12-16T12:30:00Z'],
        expect: [
            {
                signature: '5gjJdnFHzZzv8ar27YHvJYYHZ1ZQkinpd8dEERApm5fseVh2CDYhXJj9jHHNfhQSrtoeDzsmmRemSu7xnjnSbnay',
                detector: 'admin-key-behavior',
                mentions: ['after its previous signed call', 'undecoded instruction 7', 'itself paying the fee'],
            },
        ],
        only: 'admin-key-behavior',
    },
    {
        name: 'pump-fun',
        about: "Pump.fun, 2024-05-16: the withdraw authority's first flash-loan transaction, after 474 routine withdraws",
        args: ['--config', 'scripts/replays/pump-fun.yaml', '--from', '2024-05-14', '--to', '2024-05-16T15:23:00Z'],
        expect: [
            {
                signature: 'NfuqPGxbJqhxyJ4o5QB4baHzWqaPG3e2CuvjDXLuBza6RxAAwrqESu3oAH2sC5wF1b6NDRzskPaLCuMV8ZjdQHk',
                detector: 'admin-key-behavior',
                mentions: ['as fee payer or co-signer', 'also called marginfi', 'inside a flash loan'],
            },
        ],
        only: 'admin-key-behavior',
    },
];

const wanted = process.argv.slice(2);
const unknown = wanted.filter((name) => !CASES.some((c) => c.name === name));
if (unknown.length > 0) {
    console.error(`Unknown case ${unknown.join(', ')}. Cases: ${CASES.map((c) => c.name).join(', ')}`);
    process.exit(2);
}

const failures = [];
for (const c of CASES.filter((c) => wanted.length === 0 || wanted.includes(c.name))) {
    console.log(`\n=== ${c.name}: ${c.about}`);
    const json = `reports/replay-${c.name}.json`;
    const run = spawnSync('pnpm', ['-s', 'exec', 'tsx', 'src/cli.ts', 'replay', ...c.args, '--no-program-scans', '--json', json], {
        stdio: 'inherit',
    });
    const problems = run.status === 0 ? check(c, JSON.parse(readFileSync(json, 'utf8')).findings) : [`replay exited with ${run.status}`];
    if (problems.length === 0) console.log(`${c.name} OK`);
    for (const problem of problems) failures.push(`${c.name}: ${problem}`);
}

if (failures.length > 0) {
    console.error(`\nExploit replay regressed:\n${failures.map((f) => `  ${f}`).join('\n')}`);
    process.exit(1);
}
console.log('\nEvery exploit replay raised its expected alerts.');

/** Every expected finding is critical, on its transaction. */
function check(c, findings) {
    const problems = [];
    for (const e of c.expect) {
        const tx = `${e.signature.slice(0, 12)}…`;
        const found = findings.find(
            (f) =>
                f.signature === e.signature && f.detector === e.detector && f.severity === 'critical' && (!e.title || f.title === e.title),
        );
        if (!found) {
            const there = findings.filter((f) => f.signature === e.signature).map((f) => `${f.severity} [${f.detector}] ${f.title}`);
            problems.push(
                `missing critical [${e.detector}]${e.title ? ` ${e.title}` : ''} on ${tx}; found: ${there.join('; ') || 'nothing'}`,
            );
            continue;
        }
        for (const text of e.mentions ?? []) {
            if (!found.description.includes(text)) problems.push(`[${e.detector}] on ${tx} no longer says "${text}": ${found.description}`);
        }
    }
    const extra = c.only ? findings.filter((f) => f.detector === c.only && !c.expect.some((e) => e.signature === f.signature)) : [];
    for (const f of extra)
        problems.push(`unexpected ${f.severity} [${f.detector}] ${f.title} on ${f.signature?.slice(0, 12)}…: ${f.description}`);
    return problems;
}
