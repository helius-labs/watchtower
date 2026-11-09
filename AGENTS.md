# AGENTS.md

Watchtower: a local CLI that monitors Solana programs for security-relevant changes using Helius Parsed Events (history) and Parsed Streams (live).

## Working agreements

- Write the minimum code that solves the request. No speculative options, abstractions, or handling for impossible states.
- Touch only code related to the request. Match the surrounding style.
- Never swallow errors: every `catch` rethrows, returns a typed failure the caller reports, or logs with context.
- Verify against real data where possible. Decoders in `src/discover/` are tested against mainnet account fixtures; add a fixture when you change a layout.

## Comments

A comment describes what the code does, and only when that isn't self-evident from the names and types: a wire format, byte layout, API limit or quirk, unit, or an invariant a reader would otherwise break. Keep it to one line where possible. No history, motivation, incident stories, rejected alternatives or restating the next line. Prefer a better name over a comment.

## Commands

```sh
pnpm install
pnpm check         # format:check, lint, typecheck, test, build: what CI runs
pnpm format        # Prettier
pnpm lint          # oxlint (correctness rules)
pnpm test          # vitest, offline
pnpm build         # tsc → dist/
pnpm dev <command> # run the CLI from source: init | report | watch | serve | replay | test-alert
```

Run `pnpm check` before handing work back. CI also runs Gitleaks on new commits (`.github/workflows/secret-scan.yml`) and zizmor on `.github/` (`.github/workflows/zizmor.yml`, rules in `.github/zizmor.yml`): pin third-party actions to a full commit SHA with a `# vX.Y.Z` comment, set `persist-credentials: false` on checkouts, and give Dependabot ecosystems a `cooldown`.

## Layout

| Path                           | Contents                                                                                                                                                                                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/cli.ts`, `src/commands/`  | CLI entry and one file per command                                                                                                                                                                                                                            |
| `src/monitor.ts`               | Live monitoring (gap-fill, stream, IDL polling, cursors), emitting `log`/`finding`/`status` events; used by `watch` and `serve`                                                                                                                               |
| `src/server/`                  | `serve`: `node:http` server for the dashboard and its JSON API, running a `Monitor` in-process                                                                                                                                                                |
| `ui/`                          | Dashboard: plain HTML/CSS/JS, no build step, served as static files                                                                                                                                                                                           |
| `docs/`                        | User guides linked from the README: Parsed Events and Streams usage, dashboard and hosting, CLI walkthrough, detectors, discovery, grading, configuration. Update them when behavior they describe changes                                                    |
| `src/configFile.ts`            | Writing `watchtower.yaml` and `.env`; literal sink secrets move to `.env` as `${VAR}` references                                                                                                                                                              |
| `src/report/build.ts`          | Shared report assembly for `report` and the dashboard                                                                                                                                                                                                         |
| `src/helius/`                  | Thin adapters over the Helius SDK (`helius-sdk`): RPC and DAS (`rpc.ts`), Parsed Events with retries and pagination (`parsedEvents.ts`), Parsed Streams with drop detection and restarts (`parsedStreams.ts`). `sdk.ts` creates the one `createHelius` client |
| `src/model.ts`                 | `ParsedTx`, the one transaction shape every detector reads, plus converters from both APIs                                                                                                                                                                    |
| `src/discover/`                | Program, ProgramData, mint and Squads v3/v4 account decoding; admin keys (config-account fields via the IDL layout, plus admin-role signers); vaults (payout PDAs priced with DAS); IDL heuristics                                                            |
| `src/detectors/`               | Pure functions `ParsedTx → Finding[]`; registered in `index.ts`. Set `includeFailed` to also see failed transactions                                                                                                                                          |
| `src/detectors/attackChain.ts` | Links control, risk and drain findings for one protocol within 24 hours into a single critical finding                                                                                                                                                        |
| `src/engine.ts`                | Dedupe, detection, enrichment, attack-chain linking, persistence, alert dispatch                                                                                                                                                                              |
| `src/vet.ts`                   | Async enrichment: listed-token age, concentration and Token-2022 controls; admin-signer wallet age; whether an upgrade is a verified build                                                                                                                    |
| `src/configWatch.ts`           | Reads config accounts (IDL layouts) and records `config-change` findings for changed fields                                                                                                                                                                   |
| `src/discover/build.ts`        | Program bytecode hash (as `solana-verify` computes it) and the OtterSec verification lookup                                                                                                                                                                   |
| `src/discover/token2022.ts`    | Risky Token-2022 mint extensions                                                                                                                                                                                                                              |
| `src/commands/replay.ts`       | Runs every detector over a past window with a throwaway state file                                                                                                                                                                                            |
| `src/backfill.ts`              | Cursor-based Parsed Events scans                                                                                                                                                                                                                              |
| `src/idlWatch.ts`              | IDL version polling; findings recorded through `engine.record`                                                                                                                                                                                                |
| `src/targets.ts`               | Config + discovery → watch targets, scan plans, stream subscriptions                                                                                                                                                                                          |
| `src/state.ts`                 | JSON state file: cursors, signer baselines, findings                                                                                                                                                                                                          |
| `src/sinks.ts`                 | Console, Discord, Slack, Telegram, webhook                                                                                                                                                                                                                    |
| `src/report/`                  | Posture checks and terminal/HTML rendering                                                                                                                                                                                                                    |
| `test/`                        | Vitest suites; `helpers.ts` builds transactions in the Parsed Streams wire shape                                                                                                                                                                              |

## Conventions

- Instruction names are compared with `normalizeName` (lowercase, `_`/`-`/space removed), which matches how Parsed Streams compares them. Native program names come from parser-v2 (`set_authority`, `transfer_hook_extension.update`); Anchor names come from the program's IDL.
- Read decoded accounts with `account(ix, role)` and args with `arg(ix, ...keys)`. Both tolerate snake_case and camelCase.
- u64 args arrive as strings. Use `BigInt`, never `Number`, for amounts.
- Read public-key args with `pubkeyArg`. parser-v2's native decoders split a bare `Pubkey` tuple payload (for example `initialize_nonce_account`) into byte fields: the named field holds byte 0 and `field_2`..`field_32` hold the rest. `pubkeyArg` reassembles that and unwraps `COption`.
- Squads v4 transaction-buffer instructions (`transactionBufferCreate`, `transactionBufferExtend`, `vaultTransactionCreateFromBuffer`) are missing from the IDL Parsed Events holds, so they arrive undecoded with `rawData`. `decodeTransactionBuffers` in `src/discover/squads.ts` runs before the detectors: it stores buffer chunks in state and rewrites `vaultTransactionCreateFromBuffer` to read like `vaultTransactionCreate`, attaching the message only when it matches the buffer's final hash and size.
- Squads and other Anchor args decode in snake_case (`transaction_message`, `new_time_lock`). `arg` and `field` try camelCase then snake_case.
- Convert time to slots with the measured `runtime.slotMs`, never a fixed 400 ms.
- Look up rule tables with `Map`s, not plain objects, so instruction names from arbitrary IDLs can't hit prototype keys.
- A finding's `id` is `detector:signature:instructionIndex.innerIndex`. It must be stable across backfill and stream delivery.
- Set `stages` on a finding that is a step of a takeover (`control`, `risk`, `drain`); `attack-chain` links them per protocol group (`targets.groups`). Detectors are synchronous; lookups that need the network go in `src/vet.ts` and run before linking.
- Discovery runs again while monitoring after any finding that changes control (`changesAuthority` in `src/monitor.ts`); `refreshDiscovery` swaps `ctx.targets` and `runtime.plans` in place, so read them from the runtime, never from a copy taken at startup.
- Config accounts are found by constant-seed PDA, then by listing, then by sampling recent transactions (`discoverConfigAccounts`). Programs with millions of accounts cannot be listed: `getProgramAccounts` refuses them and `getProgramAccountsV2` returns empty pages with a `paginationKey`.
- `admin-key-behavior` profiles each admin key's signed transactions on its program (`StateStore.recordAdminKeyUse`) and flags departures. Transaction signers are the fee payer and signers of decoded top-level instructions; inner instructions also flag PDAs signing through CPI, so never read signers from them. Neither API sends transaction-level signers, so a key passed to an undecoded top-level call of its program counts as signing. Dormancy compares a call's time with the profile's `lastSeen`, which `startAdminKeyProfile` sets to where a key's first scan coverage begins (`backfill`, `replay`), so a key with no signed calls yet still has a quiet-since time. It was checked against the Raydium (2022-12-16) and Pump.fun (2024-05-16) exploits; keep both catching if you change it.
- Program vaults and admin keys are discovered, not configured, except `programs[].adminKeys` for programs whose IDL can't reveal them. Keys read from config accounts are kept only when they are a wallet or a Squads vault, and IDL field offsets are used only when Borsh and C-aligned layouts agree.
- Scan an admin key's own history rather than a busy program's whole stream wherever possible: Drift ran about 7 million transactions a day.
- Alerting is decided per finding (`AlertMode` in `src/engine.ts`):
  - `silent` for findings from a scan plan's first scan, which reads history from before monitoring began.
  - `queue` from `report`.
  - `send` from `watch`.
  - Undelivered alerts persist in state until every sink accepts them.
  - Grouping happens only at delivery: repeats of a non-critical alert (`groupKey`: detector, subject, title) within `alerts.groupWindowSeconds` are sent as one summary, and every finding is still recorded on its own. Never group or delay critical alerts. Stop with `engine.close()` so held repeats are sent.
- Cursors only move past scanned slots. A budget-limited scan resumes at the start of the slot it stopped in. Never advance a cursor from the stream unless that plan's gap-fill reached the present on the current connection (`caughtUp` in `src/backfill.ts`: `complete`, or a budget-limited first scan, `recent-only`).
- Styling follows the Helius design system (Orb, dev portal): Inter and IBM Plex Mono, brand orange `#E84326` used sparingly, neutral surfaces, dark and light themes.
- `assets/brand/` holds byte-for-byte copies of the official Helius brand kit (helius.dev `/Helius-Brandkit`). Never edit, recolor or redraw them. The Helius logo appears only as "Powered by Helius", never as Watchtower's own mark.

## API contracts

- Parsed Streams: `parsedTransactionSubscribe`. Max 10 programs, 50 instruction names, 100 included accounts and 20 roles per filter, and 25 subscriptions per connection. Only `confirmed` commitment. No replay or resume.
- Parsed Events scan: max 20 programs per `match`, 50 instructions and 50 discriminators per program, 10,000 transactions scanned per request. Follow `paginationToken` until it is absent.
- Call Helius only through the SDK client from `src/helius/sdk.ts`, and use the SDK's request and response types rather than redeclaring them. The one exception is the Parsed Events IDL endpoints (`/v1/parsed-events/idl/...`, documented at https://www.helius.dev/docs/api-reference/parsed-events/idl-versions and https://www.helius.dev/docs/api-reference/parsed-events/idl), which the SDK does not cover yet. A stored IDL with instructions but no account types gets its account layouts from the program's on-chain Anchor IDL account (`fetchIdl` in `src/discover/index.ts`), read through RPC.
- The SDK's `.d.ts` files use extensionless relative imports, which `moduleResolution: "NodeNext"` cannot resolve: the whole client type silently becomes `any`. Keep `"moduleResolution": "Bundler"` and explicit `.js` extensions in our own imports.
- `@solana/kit` stays on the SDK's peer range (`^6.9.0`).
- `HELIUS_RPC_URL` and `HELIUS_PARSED_STREAMS_URL` override the SDK's hosts; Parsed Events always uses the SDK's.

## Dashboard

- **Monitors:** `serve` runs one `Monitor` per config: `watchtower.yaml` (id `default`) plus `monitors/<id>.yaml`. Each has its own state file, stream connection and lifecycle, and the server keeps them in per-monitor slots.
- **API:**
  - `GET /api/state?monitor=<id>` returns that monitor's snapshot, plus `monitors`, the list for the tab bar.
  - `GET /api/events` is one server-sent event stream for all monitors. Each event's data is `{ monitor, data }`: `finding`, `status`, `log`, `report` and `state` name their monitor, and `monitors` (the list) has `monitor: null`.
  - `POST` bodies name their monitor as `monitor`: `/api/config`, `/api/pause`, `/api/resume`, `/api/reload`, `/api/report`, `/api/test-alert` and `/api/monitors/delete` (stopped or unconfigured monitors only). `/api/monitors` creates one from `{ name }`, and `/api/discover` is shared.
  - `GET /report.html?monitor=<id>` returns that monitor's HTML report.
- **Security invariants (keep them):**
  - Bind to loopback by default, and refuse public interfaces without `WATCHTOWER_PASSWORD` or `WATCHTOWER_READONLY`.
  - On loopback, accept only localhost `Host` headers.
  - `POST` requires `application/json` and a same-origin `Origin`.
  - Read-only mode rejects every `POST` and never sends config.
  - API keys and sink secrets are never sent to the browser. Literal secrets are masked, and a masked value on save means keep the stored one.
- **UI:** build DOM with `h()` in `ui/app.js` and never `innerHTML`. Findings carry on-chain strings.

## Replay

`replay` uses on-chain state as it is today for discovery, but the IDL live at the window start, and reports IDL versions activated inside the window (`idlChangesBetween`). Date edges become slots through `RpcClient.slotAtTime`, which corrects with block times; never extrapolate today's `slotMs` over months, since slot duration drifts. Keep it free of side effects: no sinks, a temporary state file, `silent` alert mode. It ends with per-detector coverage (`detectorCoverage`): `ran`, `missing-data`, `nothing-to-watch` or `live-only`, derived from each scan plan's `detectors` and outcome, so keep plans' `detectors` lists accurate and add detectors that cannot run on history to `LIVE_ONLY`. The Drift exploit (2026-03-20 to 2026-04-02, `--no-program-scans`) is the reference case and should end with a `Possible attack in progress` finding at 2026-04-01 16:05 UTC. `pnpm replay:drift` runs it against mainnet and checks for that alert (`scripts/check-drift-replay.mjs`); `.github/workflows/replay.yml` runs it weekly (Mondays) with the `HELIUS_API_KEY` repository secret and opens an issue when it fails. Run it before merging changes to detectors, discovery or the Parsed Events adapter. It costs about 35 credits.

## Adding a detector

1. Add `src/detectors/<name>.ts` exporting a `Detector`.
2. Register it in `src/detectors/index.ts`.
3. If it needs new data, extend the subscriptions and scan plans in `src/targets.ts`, keeping within the limits above. Either way, list the detector in the covering plan's `detectors` (replay coverage depends on it), or in `LIVE_ONLY` in `src/commands/replay.ts` if history can't feed it.
4. Add tests in `test/detectors.test.ts` using `tx()` and `context()` from `test/helpers.ts`.
