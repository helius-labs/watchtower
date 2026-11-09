# Watchtower

<img src="assets/dashboard.png" width="1440" alt="Watchtower dashboard: a live monitor with its security posture grade (C, 70/100), the programs, multisigs and keys it found, and findings by severity" />

Security monitoring for Solana programs. Point it at a program ID and it will:

- **Grade its security posture**: who can upgrade it and who holds admin, whether each is a single key or a multisig, the threshold and time lock, and whether admin instructions are watched.
- **Scan its history** for deployments, authority changes, multisig proposals and membership changes, new listings and risk changes, mint authority changes, and vault outflows.
- **Alert in real time** to the terminal, Discord, Slack, Telegram, or any webhook, including one critical alert when several stages of a takeover line up.
- **Replay the past**: run every detector over an earlier window, for example to see what an exploit would have triggered.

It runs on your machine with your own Helius API key, as a CLI or as a web dashboard (`watchtower serve`). There's no database or account to set up, and you can host the dashboard yourself.

Watchtower is built on two Helius APIs:

- **Parsed Events** decodes every instruction in a transaction, inner instructions included, into named args and accounts. Watchtower uses its `scan` endpoint to search an address's history server-side by program, instruction name and discriminator.
- **Parsed Streams** delivers the same decoded transactions over a WebSocket as they confirm, filtered by program, instruction name and account.

Every call goes through the [Helius TypeScript SDK](https://github.com/helius-labs/helius-sdk) (`helius-sdk`): Parsed Events, Parsed Streams, DAS, `getProgramAccountsV2` and standard Solana RPC. [How Watchtower uses Parsed Events and Parsed Streams](docs/parsed-events.md) maps each feature to the call behind it, if you want to reuse the patterns in your own app.

## Quickstart

You need Node.js 22 or later, pnpm, and a Helius API key from [dashboard.helius.dev](https://dashboard.helius.dev) with access to Parsed Events and Parsed Streams.

```sh
git clone https://github.com/helius-labs/watchtower
cd watchtower
pnpm install && pnpm build
cp .env.example .env      # then set HELIUS_API_KEY in .env
pnpm dev serve
```

Open [http://127.0.0.1:4545](http://127.0.0.1:4545), enter a program ID in the **Setup** tab, click **Discover**, then **Save**. Monitoring starts right away. Your API key is only ever read from `.env`, never typed into the browser.

Prefer the terminal? The [CLI guide](docs/cli.md) walks through `init`, `report`, `watch` and `replay` step by step.

## Documentation

| Guide                                              | Covers                                                                        |
| -------------------------------------------------- | ----------------------------------------------------------------------------- |
| [Parsed Events and Streams](docs/parsed-events.md) | How each feature uses the Helius APIs, with links to the code                 |
| [Dashboard](docs/dashboard.md)                     | The tabs, stopping and starting, several monitors, hosting it for your team   |
| [CLI](docs/cli.md)                                 | Setting up, reports, live monitoring, running unattended, replaying exploits  |
| [Detectors](docs/detectors.md)                     | Every alert and its severity, and how alerts stay complete across restarts    |
| [Discovery](docs/discovery.md)                     | Admin keys, config accounts, multisigs, vaults and builds it finds on its own |
| [Posture grade](docs/grading.md)                   | The rubric behind the grade, and how to improve it                            |
| [Configuration](docs/configuration.md)             | Environment variables, options and what scans cost in credits                 |
| [`AGENTS.md`](AGENTS.md)                           | Code layout, conventions, API limits and the dashboard's JSON API             |

## What it detects

| Detector                 | Alerts on                                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `program-deployment`     | Upgrades, upgrade-authority transfers, programs made immutable or closed                                                  |
| `upgrade-proposal`       | An upgrade or authority change proposed in the program's multisig, before it can execute                                  |
| `multisig-proposal`      | Every other proposal on a watched multisig, decoded; critical when signed with a durable nonce                            |
| `multisig-change`        | Members, threshold, time lock and spending-limit changes                                                                  |
| `mint-authority`         | Mint, freeze and Token-2022 authority and extension changes; large mints                                                  |
| `privileged-instruction` | Admin calls, classified by what they change; risky new listings; unknown signers                                          |
| `admin-key-behavior`     | A known admin key used unlike its history: after a long silence, a new instruction, fee payer or program, or a flash loan |
| `treasury-outflow`       | Large or sustained outflows and multi-asset sweeps from treasuries and vaults                                             |
| `key-authority`          | Stake, token-account and delegate authority handed off by a watched key                                                   |
| `nonce-authority`        | A durable nonce account set up for a privileged key                                                                       |
| `idl-change`             | A newly published IDL, with instructions added and removed                                                                |
| `config-change`          | Changed fields in config accounts; any admin key change is critical                                                       |
| `build-verification`     | An upgrade whose bytecode does not match a verified build                                                                 |
| `attack-chain`           | One critical alert when control, risk and drain stages of a takeover line up within 24 hours                              |

The [detector guide](docs/detectors.md) has the full rules and severities.

## Posture grade

Each program, multisig and mint starts at 100 points. A failed check costs 25 and a warning 10, and the overall grade is the lowest subject's score, because one weak link is enough for an attacker: **A** 90+, **B** 75–89, **C** 60–74, **D** 40–59, **F** below 40. The dashboard and report show what each check cost and how to fix it; the [grading guide](docs/grading.md) lists every check.

## Hosting

The dashboard binds to `127.0.0.1` by default. To share it with your team, run the Docker image on any container host with `WATCHTOWER_PASSWORD` set, or `WATCHTOWER_READONLY=true` for a public status page; it refuses to start on a public interface without one. See [hosting your own dashboard](docs/dashboard.md#host-your-own-dashboard).

## Limitations

- **Mainnet only.**
- **Upgrade authorities:** Squads v3 and v4 are recognized. SPL Governance, Realms and other PDAs are reported as unrecognized.
- **Admin instructions:** a program's own instructions are decoded only when Parsed Events has its IDL (Anchor or Program Metadata). Without one, list its admin keys under `adminKeys` so `admin-key-behavior` can watch them.
- **Live alert times:** Parsed Streams does not carry `blockTime`, so live alerts show the slot.
- **Proposals:** a Squads v4 proposal written through a transaction buffer (`vaultTransactionCreateFromBuffer`, used for large transactions such as upgrades) is decoded only when Watchtower saw the whole buffer being written, which it checks against the hash Squads stores. Approvals are linked to a v4 proposal only when `proposalCreate` ran in the same transaction that created it, as the Squads app does.
- **Treasury thresholds:** these are raw token amounts, not USD values.
- **Config accounts:** fields are read only up to the first one whose offset differs between Borsh and zero-copy layouts, and replay cannot diff them, since past account states are not stored. Replay's detector coverage lists `config-change` as live only.

## Disclaimer

Watchtower is a monitoring aid, not an audit or a guarantee. It can miss events: a detector may not recognize a new attack pattern, a program without a published IDL cannot be fully decoded, and Parsed Events and Parsed Streams are in beta. Alerts point you at activity to review; they do not prove an attack or rule one out. Keep your own incident response in place.

## Contributing

Found a bug or a gap in a detector? Open an issue or a pull request. [`CONTRIBUTING.md`](CONTRIBUTING.md) has the setup, the checklist and a walkthrough for writing a detector.

## License

MIT
