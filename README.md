# AutoRecon-XSS

Standalone XSS reconnaissance scanner (Python) — reflected, stored, DOM, blind,
upload and postMessage — with **real execution confirmation** via a headless
browser, curl PoCs, and JSON/CSV/Markdown reports.

> ⚠️ **Authorized use only.** Run this only against applications you own or for
> which you have **written authorization** (scoped pentest, in-scope bug bounty
> program, test/CTF environment such as Root-Me). The `--yes` flag confirms you
> are authorized.

---

## Installation

```bash
# Core (required)
pip install -r requirements.txt            # requests, beautifulsoup4

# Optional: browser modes (--dom, --stored-dom, --postmessage)
pip install -r requirements-dom.txt
playwright install chromium
```

---

## Quick start

**Simplest — a URL + `--all`:**
```bash
python autorecon_xss.py https://target.io/ --all --yes
```
`--all` enables every automatic mode (stored, stored-dom, dom, upload,
postMessage, headers, path) **and** loads the payload corpora. The URL can be
passed positionally (above) or with `-u/--url`. The `payloads/` files are found
automatically, regardless of the current directory.

```bash
# With scope, Markdown report, and rate-limit (recommended for bug bounty)
python autorecon_xss.py https://target.io/ --all \
  --scope 'target\.io$' --delay 0.3 --format md -o reports/target.md --yes

# Minimal reflected scan (fast) on a parameterized URL
python autorecon_xss.py "https://target.io/?q=test" --scope 'target\.io$' --yes
```

> `--all` does not turn on `--wayback` or `--blind` (they require a choice:
> archive volume / external collector). Add them when needed.

---

## XSS families and the flag that targets them

| Vulnerability class | How | Flag |
|---|---|---|
| **Reflected** (server) | input echoed in the immediate response | *(default)* |
| **Stored / second-order** | injected here, surfaces on another page | `--stored` |
| **DOM** (client sink) | `?param=`/`#hash` → client sink | `--dom` (`--dom-hash`) |
| **Stored-DOM** | login/JSON → API → `innerHTML` | `--stored-dom` |
| **Blind** (out-of-band) | surfaces in an invisible back-office | `--blind <collector>` |
| **Upload** | SVG/HTML served inline and executable | `--upload` |
| **postMessage** | `window.postMessage` → sink | `--postmessage` |
| **Mutation (mXSS)** | survives the filter, mutates on render | `--payloads payloads/mutation.txt` |
| **JSON injection** | form submitted as `application/json` | *(auto-detected)* |

> **Out of automatic reach** (irreducibly manual): logic chains — self-XSS →
> login-CSRF → bot, DOM clobbering, race conditions, escalation to RCE. The
> scanner tells you **where** and **that it executes**; assembling the exploit
> remains your job.

---

## Attack surface (injection point discovery)

| Source | Flag |
|---|---|
| Same-origin crawl (links + forms) | *(default)*, `-p/--pages N` |
| robots.txt / sitemap.xml seeding | `--sitemap` |
| External URL list (gau, katana…) | `-l urls.txt` |
| Wayback Machine historical URLs | `--wayback` (`--wayback-subdomains`, `--wayback-limit`) |
| Reflected headers (Referer, User-Agent) | `--headers` |
| Path segments (REST-like) | `--path` |
| Manual parameters (absent from the HTML) | `--param name,q,search` (`--param-method`) |
| No crawling (test a list/URL only) | `--no-crawl` |

**Scope filtering** (important in bug bounty):
- `--scope 'regex'` — allowed netlocs. **Default: same origin.** For a
  non-standard port, use `--scope 'host\.domain'` **without `$`** (the port
  breaks the `$` anchor).
- `--include 'regex'` / `--exclude 'regex'` — keep / drop URLs.

---

## Payload corpora

Files in `payloads/`, reloadable:

| File | Mode | Token |
|---|---|---|
| `bypass.txt` | reflected/stored: `--payloads` | `PROBE` |
| `mutation.txt` | reflected/stored (mXSS): `--payloads` | `PROBE` |
| `dom.txt` | execution: `--dom-payloads` | `TOKEN`, `TOKENBT` |
| `mutation-dom.txt` | execution (mXSS): `--dom-payloads` | `TOKEN`, `TOKENBT` |

- `PROBE` → random traceable marker (echo-based detection).
- `TOKEN` → `window.__arxcb('<marker>')` (invokes the instrumented callback).
- `TOKENBT` → parenthesis-free form (filters blocking `()`).
- Reflected format: `payload<TAB>contexts` (html-body, tag, attribute,
  javascript, html-comment). DOM format: one payload per line containing `TOKEN`.

```bash
# Combine several corpora
cat payloads/bypass.txt payloads/mutation.txt > payloads/all.txt
python autorecon_xss.py -u "https://app.target.io/" --stored \
  --payloads payloads/all.txt --scope 'target\.io$' --yes
```

---

## Blind XSS (out-of-band)

Injects into every point + headers probes that call back to your collector
(Interactsh, XSS Hunter, your own domain). Each point gets a unique subdomain;
the mapping is written to `blind_map.json`.

```bash
# interactsh-client gives you a domain like xxxx.oast.pro
python autorecon_xss.py -u "https://app.target.io/" \
  --blind "xxxx.oast.pro" --scope 'target\.io$' --delay 0.3 --yes
```
A hit from `x7.xxxx.oast.pro` → look up `x7` in `blind_map.json` to find which
point executed. Probes are **benign** (a plain ping, no exfiltration).

---

## Execution confirmation (headless browser)

The `--dom`, `--stored-dom`, `--postmessage` modes launch Chromium (Playwright)
and confirm execution via an instrumented callback (`window.__arxcb`). Detection
covers **all frames** (including `<iframe srcdoc>`). Benign probes: they call our
callback, with no real `alert` or data theft.

```bash
# DOM on a client param
python autorecon_xss.py -u "https://app.target.io/page?content=x" --no-crawl \
  --dom --dom-hash --scope 'target\.io$' --yes

# Stored-DOM: inject via login then observe pages in the browser
python autorecon_xss.py -u "https://app.target.io/login" --stored-dom \
  --scope 'target\.io$' --yes

# postMessage fuzzing
python autorecon_xss.py -u "https://app.target.io/" --postmessage \
  --scope 'target\.io$' --yes
```

---

## Network, rate, authentication

| Need | Flag |
|---|---|
| Authenticated session | `--cookies "session=..."` |
| Custom header (repeatable) | `--add-header 'X-Api-Key: ...'` |
| Proxy (Burp) | `--proxy http://127.0.0.1:8080` |
| Rate-limit (politeness / program rules) | `--delay 0.3` |
| Scan threads | `-t 4` |
| Network retries | `--retries 2` |
| **Global request budget** (anti-runaway guardrail) | `--max-requests 20000` |
| **Observation-page cap** (stored/stored-dom/postMessage) | `--stored-limit 30` *(default)* |
| Skip TLS verification | `--insecure` |

> **Guardrails**: the "page observation" modes (stored, stored-dom,
> postMessage) test `points × pages`, which can explode on a large site.
> `--stored-limit` caps the observed pages (default 30) and `--max-requests`
> stops the scan cleanly past a budget. On a target where the program enforces a
> low rate, combine `--delay`, `-t 1` and `--max-requests`.

---

## Reports

```bash
--format json   # machine (jq)
--format csv    # spreadsheet
--format md     # Markdown ready for a HackerOne writeup (+ curl PoC section)
-o report.md
```
Each exploitable finding ships a reproducible **curl PoC** and the **CSP** info
(which governs real exploitability). The progress bars (crawl / reflected / DOM
/ stored / upload / postMessage) print to stderr (they don't pollute a
redirected report).

---

## "Everything on" example (authorized target)

```bash
python autorecon_xss.py -u "https://app.target.io/" \
  --wayback --wayback-subdomains --path --headers \
  --stored --stored-dom --upload --postmessage \
  --dom --dom-hash --dom-payloads payloads/mutation-dom.txt \
  --payloads payloads/all.txt \
  --blind "xxxx.oast.pro" \
  --cookies "session=..." --scope 'target\.io$' \
  --delay 0.3 --threads 4 --format md -o report.md --yes
```

---

## Recommended bug bounty workflow

```bash
# 1. Surface: URL collection (external tools)
subfinder -d target.io -all -silent | httpx -silent > live.txt
cat live.txt | gau --subs > all_urls.txt
cat all_urls.txt | grep '=' | uro > params.txt

# 2. Reflected + stored detection over the surface
python autorecon_xss.py -u "https://target.io/" --no-crawl -l params.txt \
  --stored --payloads payloads/all.txt \
  --scope 'target\.io$' --delay 0.3 --format json -o scan.json --yes

# 3. DOM confirmation on the hot points
jq -r '.[]|select(.severity=="high" or .severity=="medium")|.url' scan.json \
  | sort -u > hot.txt
python autorecon_xss.py -u "https://target.io/" --no-crawl -l hot.txt \
  --dom --dom-hash --scope 'target\.io$' --delay 0.3 --yes
```

---

## Limits (honest)

- **No scanner detects "everything."** Proving the absence of XSS is
  undecidable. This tool maximizes coverage of what is **automatically
  detectable**.
- **Logic chains** (CSRF, clobbering, race, RCE) are manual.
- Blind and browser modes require a collector and Chromium respectively.
- `--postmessage` sends same-origin: a handler requiring a specific third-party
  origin may slip through.
- Respect the program's rate rules (`--delay`, few threads).
