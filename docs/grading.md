# How the posture grade works

Each program, multisig and mint is graded on its own and starts at 100 points. Every check passes, warns, fails or is just a note:

| Result       | Points |
| ------------ | ------ |
| Fail         | −25    |
| Warning      | −10    |
| Pass or note | 0      |

The overall score is the lowest subject score, because one weak link is enough for an attacker. Grades: **A** 90+, **B** 75–89, **C** 60–74, **D** 40–59, **F** below 40. The dashboard and the HTML report show each check's cost and how to fix it.

| Check                                                                                                     | Result       | How to improve                                                             |
| --------------------------------------------------------------------------------------------------------- | ------------ | -------------------------------------------------------------------------- |
| Upgrade authority is a single wallet                                                                      | Fail         | Move it to a Squads vault with a time lock, or make the program immutable  |
| Multisig needs only 1 signature                                                                           | Fail         | Raise the threshold to at least half of the voting members                 |
| Threshold below half of the voting members                                                                | Warning      | Same                                                                       |
| No time lock                                                                                              | Warning      | Set one (24 hours is common); Squads v3 needs a migration to v4            |
| Controlled multisig: a config authority can change members without a vote                                 | Warning      | Remove the config authority                                                |
| Upgrade authority is an unrecognized PDA (governance or custom)                                           | Warning      | Confirm who controls it                                                    |
| Admin key is a single wallet                                                                              | Fail         | Move admin control to a Squads multisig with a time lock                   |
| Admin multisig: threshold, time lock and config authority, graded like the upgrade multisig               | As above     | As above                                                                   |
| Admin instructions in the IDL that are not monitored                                                      | Warning      | Pick them in Setup → Programs, or list them under `privilegedInstructions` |
| Active mint or freeze authority                                                                           | Warning each | Revoke it, or move it to a multisig                                        |
| Token-2022 permanent delegate, transfer hook or non-transferable                                          | Fail each    | Remove the extension, or put its authority behind a time-locked multisig   |
| Other Token-2022 controls: pausable, frozen by default, transfer fee, close authority, interest, UI scale | Warning each | Same                                                                       |
| No verified build, or deployed bytecode that is not the registered build                                  | Warning      | Publish a verified build with `solana-verify`                              |
| A privileged key controls durable nonce accounts (found through the key's history and confirmed on-chain) | Warning      | Close accounts that are no longer needed                                   |
| Last deployment, missing IDL                                                                              | Note         | —                                                                          |
| Vaults hold Token-2022 tokens whose permanent delegate can take them                                      | Note         | —                                                                          |

Admin keys, admin multisigs and verified builds come from [automatic discovery](discovery.md).
