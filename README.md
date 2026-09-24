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
- `--ct-timeout <ms>` (default `15000`): time allowed for each CT lookup.
- `--asn-timeout <ms>` (default `20000`): time allowed for an automatic network-block lookup.
- `--remote`: try a fresh online top-domains list before falling back to the bundled list.

Filtering and connection options:

- `--port <n>` (default `443`): port to probe.
- `--no-require-h2`: allow domains that do not negotiate HTTP/2.
- `--no-require-tls13`: allow domains that do not negotiate TLS 1.3.
- `--require-authorized`: require a publicly trusted certificate chain.
- `--help`: print all options.

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
| `--ct-timeout <ms>` | 15000 | how long to wait per company when searching CT logs |
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

## Requirements

Node.js 22.6 or newer. Nothing else — no `npm install`, no other software.

Node added the ability to run TypeScript files directly in version 22.6,
but on some 22.x versions it needs an extra flag, and on later ones it
doesn't. `run.js` figures this out and retries automatically if needed —
you'll never have to think about it either way. If your Node version is
too old for this feature to exist at all, running `node run.js` will tell
you clearly instead of just crashing.

(If you also want the optional type-checking tools for editing this code —
not needed just to run it — run `npm install` once, then `npm run typecheck`.)
