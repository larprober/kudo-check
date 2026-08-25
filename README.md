# Kudo Check

Static malware analysis for repositories. Point it at a folder or a GitHub
project and it tells you whether the code behaves like malware — and if it
does, **which kind**: infostealer, RAT, ransomware, miner, dropper,
supply-chain attack, and a dozen more.

Zero dependencies. One `node` and nothing else.

```bash
node bin/kudo.js some-sketchy-repo/
```

```
  ▗▄▄▄▄▄▄▖
  ▐█▀▀▀▀█▌    KUDO CHECK  v1.0.0
  ▐█▄▄▄▄█▌    static malware analysis for repositories
   ▜██████▛
    ▝▀▀▀▀▘

╭─ VERDICT ──────────────────────────────────────────────────────────────╮
│ MALICIOUS                                                    100 / 100 │
│ ██████████████████████████████████████████████████████████████████████ │
│                                                                        │
│ Discord token grabber  ·  Infostealer  ·  high confidence              │
│ Do not run this. Do not install it. Treat any machine that already ran │
│ it as compromised.                                                     │
╰────────────────────────────────────────────────────────────────────────╯
```

## Install

Nothing to install. Node 18+ is the only requirement.

```bash
git clone <this repo> && cd kudo-check
node bin/kudo.js --help
```

Optionally put it on your PATH:

```bash
npm link
```

Then `kudo <target>` works anywhere.

## Usage

```bash
kudo .                              # scan the current project
kudo ./downloads/free-robux-tool    # scan a folder you do not trust
kudo octocat/Hello-World            # fetch and scan a GitHub repo
kudo https://github.com/user/repo   # same, full URL
kudo user/repo@dev                  # a specific branch or tag
kudo . --html report.html --open    # write and open the visual report
kudo . --json out.json --quiet      # machine-readable, for CI
kudo suspicious.exe                 # a single file works too
kudo --demo ransomware              # scan a built-in inert sample, from memory
kudo --rules                        # print the whole signature inventory
```

GitHub targets are downloaded as a tarball and analysed in memory — nothing is
written to disk and nothing from the repository is ever executed. Set
`GITHUB_TOKEN` to raise the API rate limit.

### Options

| Option | Effect |
| --- | --- |
| `--html <file>` | write the designed HTML report |
| `--open` | open that report when it is written |
| `--json [file]` | JSON to a file, or to stdout when no file is given |
| `--all` | list every detection instead of the top 40 |
| `--limit <n>` | how many detections to print (default 40) |
| `--no-explain` | drop the plain-English reason under each detection |
| `--include-deps` | also scan `node_modules`, `vendor`, `dist`, `build` |
| `--no-decode` | skip base64/hex/gzip layer decoding |
| `--no-normalize` | skip the constant-folding pass |
| `--no-strings` | skip string extraction from binaries |
| `--no-net` | never touch the network |
| `--fail-on <level>` | exit non-zero at `clean`, `lowrisk`, `suspicious`, `likely` (default) or `malicious` |
| `--demo [name]` | scan a built-in inert sample: `stealer`, `ransomware`, `rat`, `miner`, `supplychain`, `obfuscated`, `clean` |
| `--no-color`, `--quiet`, `--rules`, `--version`, `--help` | |

Exit codes: `0` below the threshold, `1` threshold met, `2` scan error.

## What it looks for

**111 signatures across 18 malware families**, plus five analysers that do not
rely on pattern matching at all.

| Family | What earns the label |
| --- | --- |
| Infostealer | browser credential stores, DPAPI unprotect, Discord tokens, wallet files, keychains, SSH and cloud credentials |
| RAT / Backdoor | reverse shells, socket-to-shell wiring, network-supplied command execution, chat-platform C2, beacon loops |
| Ransomware | recursive walk feeding an encryption routine, ransom notes, shadow copy deletion, recovery sabotage, extension marking |
| Wiper | filesystem-root deletion, raw disk and MBR overwrite, fork bombs, system directory tampering |
| Cryptominer | stratum endpoints, miner binaries, wallet in the miner user field, CPU throttling to stay unnoticed |
| Clipboard hijacker | clipboard read/write paired with wallet address substitution |
| Keylogger | global keyboard hooks, keystroke buffers flushed to disk, window-title tracking |
| Spyware | screenshot, webcam, microphone capture, victim geolocation, host fingerprint bundles |
| Loader / Dropper | download piped into a shell, fetch-write-execute, shellcode in RWX memory, in-memory assembly loading |
| Botnet | flood loops, raw sockets with spoofed headers, worker registration |
| Worm | self-copy to removable drives, `autorun.inf`, self-replication from its own image path |
| Rootkit / Evasion | Defender exclusions, AMSI bypass, ETW tampering, process hollowing, sandbox detection, unsigned driver loading, UAC bypass |
| Persistence | Run keys, Startup folder, scheduled tasks, cron, services, launch agents, WMI subscriptions |
| Supply-chain | install hooks that fetch or evaluate code, typosquatted dependencies, CI secret exfiltration, non-registry dependency sources |
| Obfuscated / Packed | `eval(atob(...))`, encoded commands, character-code reassembly, obfuscator fingerprints, zero-width and bidi characters |
| HackTool / Riskware | cross-process memory access, DLL injection, render-loop hooks, LSASS dumping |
| Phishing | cloned brand login forms, credentials POSTed elsewhere, seed-phrase capture |
| Adware / PUP | homepage and search hijacking, ad injection, silent bundled installers |

Beyond signatures:

- **Layer decoding.** Base64, hex, `\x` escapes, URL-encoding, character-code
  arrays and gzip/deflate blobs are decoded up to two levels deep and rescanned.
  A payload hidden inside an encoded string is reported at the line that hides
  it, with the encoding named. An embedded PE/ELF gets its own critical finding.
- **Constant folding.** Before matching, a second normalised view of each file
  is built: adjacent string literals folded (`"Log" + "in Data"`),
  single-assignment constants substituted, escape sequences resolved, reverse
  idioms (`[::-1]`, `.reverse().join('')`) and list joins collapsed.
  Only detections invisible in the raw text are kept, and they are weighted
  **up**: writing a string in pieces to dodge a scanner is itself evidence.
- **Entropy analysis.** Source that does not look hand-written — extreme
  entropy, single lines of tens of thousands of characters — is flagged, with
  minified bundles excluded.
- **Binary triage.** PE/ELF/Mach-O/MSI/DEX identification, packer detection
  (UPX, Themida, VMProtect, ConfuserEx, PyInstaller, Nuitka), SHA-256, entropy,
  and a `strings` pass that runs the full signature set over what it extracts.
- **Manifest analysis.** `package.json`, `requirements.txt`, and CI workflows
  are parsed rather than grepped: install hooks, typosquats (edit distance with
  transposition), non-registry sources, and workflows that pipe secrets out.
- **Repository signals.** For GitHub targets: age, stars, fork status, license,
  and time since the last commit. A three-day-old repository with no stars is
  not proof of anything, and the report says so.

## What can it scan?

Anything you can read. It needs no privileges, installs nothing, and never
executes what it looks at.

| Target | What happens |
| --- | --- |
| A folder | walked recursively; `.git`, `node_modules`, `vendor`, `dist` skipped unless `--include-deps` |
| A single file | scanned on its own, source or binary |
| A GitHub repo | downloaded as a tarball, unpacked in memory, scanned, discarded |
| Source code | full signature set, layered decoding, entropy analysis |
| Executables (`.exe`, `.dll`, `.so`, dylib, MSI, DEX) | format identified, packers detected, SHA-256 and entropy recorded, and every extracted string run through the full signature set |
| Manifests and CI config | parsed properly, not grepped |

What it will **not** do well, stated plainly:

- **Archives are not unpacked.** A `.zip`, `.jar`, `.apk` or `.7z` is
  identified and hashed, but its contents are compressed, so the string pass
  sees very little. Extract it first and scan the folder.
- **Compiled binaries are triaged, not reverse-engineered.** Strings and
  packer detection catch careless malware. They do not catch careful malware.
- **Media files are skipped** below 4 MB, and any file over 12 MB is skipped.
- **Encrypted or password-protected content** is opaque to it, as it is to
  every static scanner.

### A note on your antivirus

Detection fixtures look like malware — that is their job. Windows Defender
quarantined one during development while it sat on disk as an ordinary
`.py` file. So the corpus now lives base64-encoded in `test/corpus.js` and is
decoded straight into memory; nothing malware-shaped is ever written to disk.
Clone this repository and your antivirus will stay quiet.

Read any sample with:

```bash
node test/corpus.js show stealer
```

## How the verdict is decided

Detections do not simply add up. Each rule contributes its weight once, with a
25% bonus per additional file it appears in (capped at 2×), then:

- findings in test, fixture and documentation paths are weighted at **0.3**
- findings inside a decoded blob are weighted at **1.3** — hiding is evidence
- findings in dependency manifests are weighted at **1.15** — they run on install
- each family is capped, and cannot be **named** until it clears two gates:
  a minimum number of distinct signatures, and required corroborating
  behaviour

That second gate is what keeps the output honest. A file that encrypts other
files is not ransomware; a file that encrypts other files **and** deletes shadow
copies is. AES alone gets you a backup tool.

The strongest family sets the score, other families corroborate at 32%, and
below 36/100 no malware name appears in the headline at all — a weak partial
match is a lead, not a diagnosis.

Verdict bands: **Clean** (0–13), **Low Risk** (14–35), **Suspicious** (36–61),
**Likely Malicious** (62–84), **Malicious** (85+).

## The HTML report

`--html report.html` writes a single self-contained file: risk gauge, family
cards with a drawn icon per malware class, an ATT&CK-flavoured capability
profile, filterable detections with the reasoning attached, indicators, binary
artifacts with hashes, and repository signals. It adapts to light and dark, it
prints, and it makes zero network requests.

## Accuracy

`npm test` runs 53 checks: unit tests for the decoder, tar reader, typosquat
distance and classifier gating, plus end-to-end classification of six inert
sample repositories and a false-positive control that must come back clean.
All fixture material is decoded into memory; the suite touches no malware-shaped
files on disk.

Measured against real projects:

| Repository | Files | Verdict | Score |
| --- | --- | --- | --- |
| expressjs/express | 213 | Clean | 0 |
| pallets/flask | 236 | Clean | 0 |
| psf/requests | 128 | Clean | 1 |
| axios/axios | 466 | Clean | 1 |

Every false positive found during development became a signature fix, and the
reasoning is recorded in the rule comments.

### Evasion resistance

The same two indicators, written six ways. Every obfuscated variant scores
at least as high as the plain one, because hiding adds to the score:

| How it is written | Verdict | Score |
| --- | --- | --- |
| plain source | Suspicious | 54 |
| split string literals | Likely Malicious | 65 |
| reversed literals | Likely Malicious | 65 |
| list-join indirection | Likely Malicious | 65 |
| hex escapes | Likely Malicious | 80 |
| base64 blob | Malicious | 86 |

Before the folding pass, four of those five obfuscations scored **zero**.

## In CI

```yaml
- name: Malware scan
  run: node bin/kudo.js . --fail-on suspicious --quiet --json kudo.json
```

## Limits — read these

Kudo Check is a **static** analyser. It reasons about code as written.

- It cannot see what a program does at runtime, what a compiled binary really
  contains, or what a server chooses to return to a downloader.
- It folds constants but it does not **parse**. There is no AST and no taint
  tracking, so it cannot prove a credential read flows into a network send —
  it infers from what appears together. Indirection it cannot resolve
  statically (values assembled at runtime, fetched from a server, or
  decrypted with a key) still gets past it.
- A clean result is evidence, not proof. It means nothing in this project
  matched 111 signatures and five analysers — which is worth something, and is
  not the same as "safe".
- Dual-use tooling is genuinely ambiguous. A debugger, a pentest kit and a RAT
  share a lot of code. That is why findings come with reasons: the tool is
  meant to inform your judgement, not replace it.

If a scan comes back malicious on something you already ran, treat the machine
as compromised: the credentials on it are the first thing to rotate.

## Layout

```
bin/kudo.js            entry point
src/cli.js             argument parsing, output routing, exit codes
src/index.js           scan orchestration
src/core/walk.js       file discovery, context discounting
src/core/scan.js       signature matching, decoding, binary triage
src/core/classify.js   scoring, family gating, verdict
src/core/decode.js     layered decoder
src/core/normalize.js  constant folding / de-obfuscation
src/core/entropy.js    entropy and "not hand-written" heuristics
src/core/binary.js     executable identification, strings
src/core/manifest.js   package.json / requirements / CI analysis
src/rules/             signatures, family taxonomy, package lists
src/net/               GitHub fetch, tar reader
src/report/            terminal, HTML and icon rendering
test/run.js            53-check suite
test/corpus.js         inert fixture corpus, base64, decoded into memory
```

The corpus in `test/corpus.js` holds **inert fixtures**: guards are constant
false, every network target is loopback, and nothing is executable. They exist
so the classifier can be tested honestly.

## License

MIT
