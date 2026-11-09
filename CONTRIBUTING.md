# Contributing

Thanks for helping make Solana programs safer to depend on.

## Setup

You need Node.js 22 or later, pnpm, and a [Helius API key](https://dashboard.helius.dev) for anything that talks to mainnet.

```sh
pnpm install
cp .env.example .env   # then set HELIUS_API_KEY
pnpm check             # format, lint, typecheck, tests, build
```

The tests run offline and never spend API credits.

## Before you open a pull request

- Run `pnpm check`. CI runs the same steps.
- CI also scans each push and pull request for secrets (Gitleaks) and audits workflow changes (zizmor). Pin any third-party GitHub Action to a full commit SHA with its version as a comment; `actions/*` may use a version tag.
- If you changed detectors, discovery or the Helius adapters, also run `pnpm replay:check`. It replays the Drift, Raydium and Pump.fun exploits against mainnet with your API key (about 190 credits) and checks Watchtower still raises a critical alert on each attack's first transaction. `pnpm replay:check raydium` runs one case. A weekly workflow runs the same check.
- `pnpm format` fixes formatting; `pnpm lint` runs oxlint.
- Read [`AGENTS.md`](AGENTS.md). It covers the layout, the conventions (naming, comments, how detectors read decoded instructions) and the invariants that keep alerts complete, such as when a cursor may move.
- Add tests for new behavior. Detectors are tested with the helpers in [`test/helpers.ts`](test/helpers.ts), which build transactions in the Parsed Streams wire shape. When you change an account decoder, add a fixture from a real mainnet account.
- Keep changes focused. A new detector, a bug fix and a refactor are easier to review as separate pull requests.

## Adding a detector

A detector is a pure function from a decoded transaction to findings:

```ts
import { account, nameOf } from '../model.js';
import { findingFor, type Detector } from './types.js';

export const oracleChange: Detector = {
  id: 'oracle-change',
  description: 'Oracle account swapped on a watched market',
  detect(tx, ctx) {
    return tx.instructions
      .filter((ix) => ctx.targets.programs.has(ix.programId) && nameOf(ix) === 'updateoracle')
      .map((ix) =>
        findingFor('oracle-change', tx, ix, {
          severity: 'high',
          title: 'Oracle changed',
          description: `Oracle set to ${account(ix, 'new_oracle')?.pubkey}`,
          subject: ix.programId,
          subjectLabel: ctx.targets.programs.get(ix.programId)!.label,
          details: {},
        }),
      );
  },
};
```

1. Register it in [`src/detectors/index.ts`](src/detectors/index.ts).
2. Add tests in [`test/detectors.test.ts`](test/detectors.test.ts) using the helpers in [`test/helpers.ts`](test/helpers.ts).
3. Add its id to the `detectors` of the scan plan that finds its transactions (`scanPlans` in [`src/targets.ts`](src/targets.ts)), so `replay` reports whether it covered the window. If it needs state that history can't provide, add it to `LIVE_ONLY` in [`src/commands/replay.ts`](src/commands/replay.ts) instead.

If a detector targets a real exploit, a `watchtower replay` of the exploit window is the most convincing test. The existing detectors are listed in [`docs/detectors.md`](docs/detectors.md).

## Reporting bugs

Open an issue with what you ran, what you expected and what happened, plus the relevant log lines with your API key removed.
