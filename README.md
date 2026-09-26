# Reality SNI Scanner

[فارسی](README.fa.md)

Finds good SNI/DEST domains for an Xray Reality config, automatically.
You don't give it a list of domains to try — it builds that list itself,
tests each one with a real TLS connection, and shows you the best picks.

---

## Before you start

> [!IMPORTANT]
> **Node.js v22.6.0 or newer is required.** It is the only installation
> needed to run this scanner. You do **not** need `npm install`.

Check your installed version:

```powershell
node --version
```

If Node.js is missing or older than v22.6.0, install the current LTS release
from [nodejs.org](https://nodejs.org/en/download).

**[Quick start](#quick-start)** · **[Discovery methods](#the-three-ways-it-finds-domains)** · **[Flags](#flags)** · **[فارسی](README.fa.md)**

---

## Quick start

After installing Node.js, open a terminal in this folder and run:

```powershell
node run.js
```

That's it. It will:

1. Load a built-in list of a few hundred well-known domains (no internet needed for this step).
2. Try a real TLS connection to each one.
3. Print the ones that qualify, fastest first.
4. Search Certificate Transparency logs for subdomains of the top picks and probe them too.
5. Merge everything, deduplicate, and print the best candidates.
6. Re-test the best of them through a real Xray Reality tunnel and print the ones that actually carry traffic, fastest first.

Steps 5-6 download Xray itself on the first run (see
[The three stages](#the-three-stages)); add `--reality-test 0` if you
only want the quick TLS results.

At the bottom it prints something like this, ready to paste into your Xray config:

```
"dest": "pl.wikipedia.org:443",
"serverNames": ["pl.wikipedia.org"]
```

## Why it's built this way

**Run it without a VPN.** The goal is to find domains that work well for
your real users, on your real (filtered) internet connection. If you run
this scan through a VPN, you're measuring the VPN's connection, not the one
your actual users have — the results would be meaningless.

**No list to fetch first.** Earlier versions of this tool needed to
download a domain list from GitHub before it could start. That was a
problem: if GitHub is also blocked or slow for you, you'd need a VPN just
to *build* the list — which then forces you to break the rule above. So
now the list ships inside the tool itself. Nothing to download first.

**Run it on the Xray server too.** A local scan measures the path from your
current machine to the candidate domain. It does *not* prove that the Xray
server can reach that domain as a Reality `dest`. After narrowing the list
locally, copy the project to the Xray host and run the same command there;
that second scan validates the server-to-DEST path and should decide the
final pick.

## What makes a domain a good pick

For Reality to work, the domain you borrow needs to:
- Support **TLS 1.3** (a specific, modern version of the encryption Reality relies on)
- Support **HTTP/2** (what modern browsers normally use — makes the fake handshake look current)
- Respond **fast** from where you actually are
- Present a real certificate (the report records whether its chain is publicly trusted)

The scanner checks all four automatically for every domain it tries. Public
certificate trust is reported but not required by default because Reality can
operate without it; add `--require-authorized` when that is your policy.

## The three stages

The scan runs in three stages, and they answer different questions.

**Stage 1 — the quick TLS test.** For every candidate domain it opens a real
TLS 1.3 connection and checks the four things listed above. It takes seconds,
downloads nothing, and works with no arguments at all: `node run.js`. This is
the first table it prints.

**Stage 1.5 — subdomain discovery (optional).** Discovery starts in the
background while Stage 1 probes, then the tool takes the top domains and
searches for their subdomains (e.g., `www.google.com` → `accounts.google.com`,
`mail.google.com`, etc.). Each discovered subdomain gets probed with the same
TLS handshake as Stage 1, and the results are merged with Stage 1 (deduplicated
by base domain). This finds faster, less-common subdomains that make better
Reality disguises.

Discovery walks a fallback chain under one wall-clock budget (`--ct-timeout`,
default 10 s): **crt.sh → Cert Spotter → DNS brute-force**. The first source
that returns names for a base domain wins; if a provider is down, times out or
returns nothing, the next one is tried automatically (a provider that fails is
skipped for the rest of the run). Everything learned is cached in
`ct-cache.json` next to `results.json` for 7 days, so a repeat scan of the
same domains needs no network at all — `--ct-refresh` forces a refetch and
`--no-ct` skips Phase 1.5 entirely. Because discovery runs concurrently with
Stage 1, its log lines (prefetch start, cache hits, source failures) print
after `results.json` is written, and the Phase 1.5 table header carries a
`[coverage: ...]` note showing which sources actually answered — including
`cache` for names served from disk.

> [!NOTE]
> crt.sh is a free, shared service with poor uptime — which is exactly why
> it is only the *first* source in the chain. If every source fails,
> Phase 1.5 reports the reasons and the run continues with Stage 1 + Stage 2
> results.

**Stage 2 — a full Reality tunnel test.** Answering TLS is not automatically
enough to be a usable Reality `dest`. Xray does one extra thing with that
domain: when a client connects, the server forwards the client's TLS
handshake to the dest and uses the *real* site's reply as the template for its
own answer. So a domain can pass Stage 1 and still be useless in practice.

Stage 2 finds out for real. It takes the best candidates from Stage 1 +
Stage 1.5 (merged and deduplicated) and, for each one, starts a temporary pair
of Xray processes — a server whose `dest` is that domain, and a client that
tunnels through it — then pushes a 512 KB upload down the tunnel and times it:

```
this machine --TCP--> [Xray client] ==REALITY==> [Xray server] --TCP--> this machine
```

Everything is killed again as soon as the measurement is done. A domain that
carried the upload is proven to work as a `dest`, and the measured speed is
what decides the final pick, so the suggestion at the end of the run comes from
the fastest domain that actually completed a tunnel — not from the fastest
TLS handshake. Domains that fail the tunnel are still listed, with the reason.

This stage costs real time — roughly 5–15 s per candidate, since Xray probes
the dest while it starts — which is why it only runs on the top candidates.
`--reality-test <n>` changes how many are tested; `--reality-test 0` skips it
and leaves you with the Stage 1 table only.

**You do not need to install Xray yourself.** The first time a run uses
Stage 2, the tool downloads the official Xray-core build for your operating
system into a `bin` folder next to `run.js` (about 20 MB, once) and reuses it
afterwards. If that download fails — GitHub blocked, say — the Stage 1 results
are already saved, and the tool says what happened and carries on rather than
losing the run. If you already have Xray on the machine, `--xray <path>` uses
that copy instead of downloading one.

## The three ways it finds domains

You can use any combination of these together.

### 1. Built-in list (always on, no setup)

Runs by default. A snapshot of a few hundred major, well-known websites.

### 2. Domains near your own server (optional)

```bash
node run.js --neighbors --prefix 168.222.43.0/24
```

Your hosting provider owns a whole block of IP addresses, not just yours.
This looks for other real websites hosted in that same block. A domain
that's genuinely close to your server (network-wise) makes a more
convincing disguise than a random big name, because the routing and timing
match your server more naturally.

**Finding your block (the CIDR):** run this in PowerShell, replacing the IP
with your own server's IP:

```powershell
(Invoke-RestMethod "https://stat.ripe.net/data/network-info/data.json?resource=YOUR_SERVER_IP").data
```

It prints a `prefix` value like `168.222.43.0/24` — that's what goes after `--prefix`.

If you skip `--prefix` and pass `--target YOUR_SERVER_IP` instead, the tool
will try to look this up for you automatically. This can fail on a slow or
filtered connection, which is why looking it up yourself and passing
`--prefix` directly is the more reliable option.

### 3. Certificate Transparency logs (optional)

```bash
node run.js --ct
```

Every real HTTPS certificate ever issued is recorded in a public, permanent
log (this is required by browser makers — it's not a leak). This searches
those logs for real, obscure subdomains of big trusted companies — things
like `delivery.mp.microsoft.com` — that would never show up in a normal
"top websites" list because nobody links to them, but that make excellent,
less-commonly-used disguise domains.

### Using all three together

```bash
node run.js --neighbors --prefix 168.222.43.0/24 --ct
```

Everything gets combined into one list, duplicates removed, then every
domain gets the same TLS test. The results table shows which method found
each one, in a `source` column.

## Flags

Use `node run.js --help` for the authoritative command reference. Common
options are grouped here so the README stays readable on narrow screens.

- `--candidates <n>` (default `400`): number of bundled domains to probe.
- `--top <n>` (default `15`): number of qualifying domains printed to the terminal.
- `--concurrency <n>` (default `40`): simultaneous TLS probes.
- `--timeout <ms>` (default `4000`): maximum time per TLS connection.
- `--out <file>` (default `results.json`): full JSON report location.

Optional discovery sources:

- `--neighbors`: add reverse-DNS candidates near the supplied server network.
- `--target <ip>`: server IPv4 address used to look up its network block.
- `--prefix <cidr>`: network block to sample directly, such as `168.222.43.0/24`.
- `--sample <n>` (default `200`): IPs sampled from that block.
- `--ct`: add Certificate Transparency subdomains.
- `--ct-seeds <list>`: comma-separated domains to search in CT logs.
- `--ct-limit <n>` (default `300`): maximum CT domains collected; each response is capped at 5 MiB.
- `--ct-timeout <ms>` (default `10000`): total wall-clock budget for one CT
  discovery phase, shared by every source, retry and fallback in the chain.
- `--ct-source <name>` (default `auto`): which source discovery may use —
  `auto` (crt.sh → Cert Spotter → DNS brute-force), `crtsh`, `certspotter`
  or `dns`.
- `--ct-refresh`: ignore the `ct-cache.json` disk cache and refetch everything.
- `--no-ct`: skip Phase 1.5 subdomain discovery entirely.
- `--asn-timeout <ms>` (default `20000`): time allowed for an automatic network-block lookup.
- `--remote`: try a fresh online top-domains list before falling back to the bundled list.

Filtering and connection options:

- `--port <n>` (default `443`): port to probe.
- `--no-require-h2`: allow domains that do not negotiate HTTP/2.
- `--no-require-tls13`: allow domains that do not negotiate TLS 1.3.
- `--require-authorized`: require a publicly trusted certificate chain.
- `--help`: print all options.

Reality tunnel test (Stage 2):

- `--reality-test <n>` (default `10`): how many top Stage-1 candidates to
  re-test through a real tunnel; `0` disables this stage.
- `--reality-upload-kb <n>` (default `512`): size of the test upload.
- `--reality-concurrency <n>` (default `2`, max `4`): tunnels to test at once.
  Each one runs two Xray processes, so keep this low.
- `--xray <path>`: use an Xray binary you already have instead of the
  automatically downloaded one.

<!-- Legacy table retained in source; the compact list above is used because the table is unreadable on narrow GitHub layouts.
| Flag | Default | What it does |
|---|---|---|
| `--candidates <n>` | 400 | how many domains to try from the built-in list |
| `--neighbors` | off | also look for domains near your own server (see method 2 above) |
| `--target <ip>` | — | your server's IP (used to look up its network block automatically) |
| `--prefix <cidr>` | — | give the network block directly, skipping the automatic lookup |
| `--sample <n>` | 200 | how many IPs to check in that block |
| `--ct` | off | also search Certificate Transparency logs (see method 3 above) |
| `--ct-seeds <list>` | microsoft.com,google.com,apple.com,cloudflare.com,amazon.com,akamai.com,fastly.net,wikipedia.org,github.com,mozilla.org | comma-separated companies to search |
| `--ct-limit <n>` | 300 | max results to pull from those logs (each response is also capped at 5 MiB) |
| `--remote` | off | download a fresh domain list instead of using the built-in one (needs internet reachable without a VPN — see "Why it's built this way" above) |
| `--concurrency <n>` | 40 | how many domains to test at the same time |
| `--timeout <ms>` | 4000 | how long to wait for each domain before giving up |
| `--asn-timeout <ms>` | 20000 | how long to wait for the automatic network-block lookup (raise this if your connection is slow) |
| `--ct-timeout <ms>` | 10000 | total wall-clock budget for one CT discovery phase (shared by every source, retry and fallback) |
| `--ct-source <name>` | auto | which CT source discovery may use: auto (crt.sh → Cert Spotter → DNS brute-force), crtsh, certspotter, dns |
| `--ct-refresh` | off | ignore the ct-cache.json disk cache and refetch everything |
| `--no-ct` | off | skip Phase 1.5 subdomain discovery entirely |
| `--port <n>` | 443 | which port to test (443 is the standard HTTPS port — leave this alone unless you know why you'd change it) |
| `--top <n>` | 15 | how many results to show |
| `--out <file>` | results.json | where to save the full results, including failed ones |
| `--no-require-h2` | — | don't require HTTP/2 support |
| `--no-require-tls13` | — | don't require TLS 1.3 |
| `--require-authorized` | off | require a certificate trusted by a public authority (Reality doesn't actually need this) |
| `--help` | — | show all options |

-->

## Reading the results

Each row shows: the domain, which method found it, the TLS version it
supports, whether it supports HTTP/2, how long the connection took in
milliseconds, and whether its certificate is fully trusted.

Faster (lower `ms`) is better, but also worth weighing: a domain nobody
else uses as a Reality disguise is arguably safer than a very common
choice like `www.google.com` — popular picks are exactly the ones
censors are most likely to have specifically profiled.

The full results (including every domain that failed, and why) are saved
to `results.json`, in case you want to look closer later.

If Phase 1.5 ran, it prints a table of discovered subdomains before the
merged results. The `ct-subdomain` source in the final table indicates a
domain found via the CT discovery chain (crt.sh, Cert Spotter or DNS
brute-force); the `[coverage: ...]` note in the Phase 1.5 table header shows
which sources actually answered for this run, `cache` meaning the names came
from `ct-cache.json` instead of the network.

If Stage 2 ran, it prints a second table underneath: the domain, its handshake
time, the upload speed measured through the tunnel in kbps, and
whether the tunnel worked at all. The `ok` rows are the ones proven usable as a
`dest`; the failed ones list the reason Xray gave. The same data, for all
stages, is in `results.json` under `stage2`.

## Common issues

- **Stage 2 takes minutes:** that is expected — it is timing real tunnels.
  Lower the cost with `--reality-test 3`, or skip the stage with
  `--reality-test 0`.
- **"stage 2 skipped: ..." with a download error:** the Xray download failed
  (usually GitHub being blocked). The Stage 1 results are still in
  `results.json`; retry later, or point the tool at an Xray you already have
  with `--xray <path>`.
- **"phase 1.5: ..." source failures, or "no subdomains passed filtering":**
  CT providers go down regularly (crt.sh in particular), and CT logs contain
  many historical subdomains that no longer exist. Discovery automatically
  falls back from crt.sh to Cert Spotter to DNS brute-force within the
  `--ct-timeout` budget, so a dead provider only costs time — if *every*
  source fails, the run still finishes with Stage 1 + Stage 2 results and a
  per-source reason in the log. Retry later (or run with `--ct-refresh` once
  providers are healthy) if you want subdomain discovery.
- **No qualifying domains:** try a larger candidate pool, for example
  `node run.js --candidates 1000`. For troubleshooting only, you can relax
  the HTTP/2 requirement with `--no-require-h2`.
- **Many connections time out:** check your internet connection, DNS,
  firewall rules, and whether the default `--timeout 4000` is long enough
  for your network.
- **The candidate works locally but not on the VPS:** run the scanner on the
  Xray server and choose from that result; local measurements cannot verify
  the server-to-DEST path.
- **Node.js is too old:** install Node.js v22.6.0 or newer, then retry.

## Requirements

Node.js 22.6 or newer. Nothing else — no `npm install`, no other software.
The Xray binary Stage 2 needs is downloaded for you, on first use, into a
`bin` folder next to `run.js`.

Node added the ability to run TypeScript files directly in version 22.6,
but on some 22.x versions it needs an extra flag, and on later ones it
doesn't. `run.js` figures this out and retries automatically if needed —
you'll never have to think about it either way. If your Node version is
too old for this feature to exist at all, running `node run.js` will tell
you clearly instead of just crashing.

(If you also want the optional type-checking tools for editing this code —
not needed just to run it — run `npm install` once, then `npm run typecheck`.)
