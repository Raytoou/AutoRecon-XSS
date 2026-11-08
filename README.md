# AutoRecon-XSS

Scanner de reconnaissance XSS autonome (Python) — réfléchi, stored, DOM, blind,
upload et postMessage — avec **confirmation d'exécution réelle** via navigateur
headless, PoC curl, et rapports JSON/CSV/Markdown.

> ⚠️ **Usage légal uniquement.** À n'exécuter que sur des applications dont vous
> êtes propriétaire ou pour lesquelles vous disposez d'une **autorisation écrite**
> (pentest avec périmètre, programme de bug bounty in-scope, environnement de
> test / CTF comme Root-Me). Le flag `--yes` confirme que vous êtes autorisé.

---

## Installation

```bash
# Cœur (obligatoire)
pip install -r requirements.txt            # requests, beautifulsoup4

# Optionnel : modes navigateur (--dom, --stored-dom, --postmessage)
pip install -r requirements-dom.txt
playwright install chromium
```

---

## Démarrage rapide

**Le plus simple — une URL + `--all` :**
```bash
python autorecon_xss.py https://cible.io/ --all --yes
```
`--all` active tous les modes automatiques (stored, stored-dom, dom, upload,
postMessage, headers, path) **et** charge les corpus de payloads. L'URL peut être
donnée en positionnel (ci-dessus) ou avec `-u/--url`. Les fichiers `payloads/`
sont trouvés automatiquement, quel que soit le dossier courant.

```bash
# Avec périmètre, rapport Markdown, et rate-limit (recommandé en bug bounty)
python autorecon_xss.py https://cible.io/ --all \
  --scope 'cible\.io$' --delay 0.3 --format md -o reports/cible.md --yes

# Scan réfléchi minimal (rapide) sur une URL paramétrée
python autorecon_xss.py "https://cible.io/?q=test" --scope 'cible\.io$' --yes
```

> `--all` n'allume pas `--wayback` ni `--blind` (ils nécessitent un choix :
> volume d'archives / collecteur externe). Ajoute-les au besoin.

---

## Les familles de XSS et le flag qui les vise

| Classe de vulnérabilité | Comment | Flag |
|---|---|---|
| **Réfléchie** (serveur) | input renvoyé dans la réponse immédiate | *(défaut)* |
| **Stored / second-ordre** | injecté ici, ressort sur une autre page | `--stored` |
| **DOM** (sink navigable) | `?param=`/`#hash` → sink client | `--dom` (`--dom-hash`) |
| **Stored-DOM** | login/JSON → API → `innerHTML` | `--stored-dom` |
| **Blind** (out-of-band) | ressort dans un back-office invisible | `--blind <collecteur>` |
| **Upload** | SVG/HTML servi inline exécutable | `--upload` |
| **postMessage** | `window.postMessage` → sink | `--postmessage` |
| **Mutation (mXSS)** | survit au filtre, mute à l'affichage | `--payloads payloads/mutation.txt` |
| **Injection JSON** | formulaire soumis en `application/json` | *(auto-détecté)* |

> **Hors de portée automatique** (irréductiblement manuel) : les chaînes
> logiques — self-XSS → login-CSRF → bot, DOM clobbering, race conditions,
> escalade vers RCE. Le scanner vous dit **où** et **que ça exécute** ;
> l'assemblage de l'exploit reste votre travail.

---

## Surface d'attaque (découverte des points d'injection)

| Source | Flag |
|---|---|
| Crawl même-origine (liens + formulaires) | *(défaut)*, `-p/--pages N` |
| Amorçage robots.txt / sitemap.xml | `--sitemap` |
| Liste d'URLs externe (gau, katana…) | `-l urls.txt` |
| URLs historiques Wayback Machine | `--wayback` (`--wayback-subdomains`, `--wayback-limit`) |
| En-têtes réfléchis (Referer, User-Agent) | `--headers` |
| Segments de path (REST-like) | `--path` |
| Paramètres manuels (absents du HTML) | `--param name,q,search` (`--param-method`) |
| Ne pas crawler (tester liste/URL seule) | `--no-crawl` |

**Filtrage de périmètre** (important en bug bounty) :
- `--scope 'regex'` — netloc autorisés. **Défaut : même origine.** Pour un port
  non-standard, utiliser `--scope 'host\.domaine'` **sans `$`** (le port casse
  l'ancre `$`).
- `--include 'regex'` / `--exclude 'regex'` — garder / ignorer des URLs.

---

## Corpus de payloads

Fichiers dans `payloads/`, rechargeables :

| Fichier | Mode | Jeton |
|---|---|---|
| `bypass.txt` | réfléchi/stored : `--payloads` | `PROBE` |
| `mutation.txt` | réfléchi/stored (mXSS) : `--payloads` | `PROBE` |
| `dom.txt` | exécution : `--dom-payloads` | `TOKEN`, `TOKENBT` |
| `mutation-dom.txt` | exécution (mXSS) : `--dom-payloads` | `TOKEN`, `TOKENBT` |

- `PROBE` → marqueur aléatoire traçable (détection par écho).
- `TOKEN` → `window.__arxcb('<marqueur>')` (appel du callback instrumenté).
- `TOKENBT` → forme sans parenthèses (filtres bloquant `()`).
- Format reflected : `payload<TAB>contexts` (html-body, tag, attribute,
  javascript, html-comment). Format DOM : un payload par ligne contenant `TOKEN`.

```bash
# Combiner plusieurs corpus
cat payloads/bypass.txt payloads/mutation.txt > payloads/all.txt
python autorecon_xss.py -u "https://app.cible.io/" --stored \
  --payloads payloads/all.txt --scope 'cible\.io$' --yes
```

---

## Blind XSS (out-of-band)

Injecte dans tous les points + en-têtes des sondes qui rappellent votre
collecteur (Interactsh, XSS Hunter, votre domaine). Chaque point reçoit un
sous-domaine unique ; la correspondance est écrite dans `blind_map.json`.

```bash
# interactsh-client vous donne un domaine type xxxx.oast.pro
python autorecon_xss.py -u "https://app.cible.io/" \
  --blind "xxxx.oast.pro" --scope 'cible\.io$' --delay 0.3 --yes
```
Un hit depuis `x7.xxxx.oast.pro` → cherchez `x7` dans `blind_map.json` pour
savoir quel point a exécuté. Sondes **bénignes** (simple ping, pas d'exfiltration).

---

## Confirmation d'exécution (navigateur headless)

Les modes `--dom`, `--stored-dom`, `--postmessage` lancent Chromium (Playwright)
et confirment l'exécution via un callback instrumenté (`window.__arxcb`). La
détection couvre **toutes les frames** (y compris `<iframe srcdoc>`). Sondes
bénignes : elles appellent notre callback, sans `alert` réel ni vol de données.

```bash
# DOM sur un param client
python autorecon_xss.py -u "https://app.cible.io/page?content=x" --no-crawl \
  --dom --dom-hash --scope 'cible\.io$' --yes

# Stored-DOM : injecte via login puis observe les pages dans le navigateur
python autorecon_xss.py -u "https://app.cible.io/login" --stored-dom \
  --scope 'cible\.io$' --yes

# Fuzzing postMessage
python autorecon_xss.py -u "https://app.cible.io/" --postmessage \
  --scope 'cible\.io$' --yes
```

---

## Réseau, débit, authentification

| Besoin | Flag |
|---|---|
| Session authentifiée | `--cookies "session=..."` |
| En-tête personnalisé (répétable) | `--add-header 'X-Api-Key: ...'` |
| Proxy (Burp) | `--proxy http://127.0.0.1:8080` |
| Rate-limit (politesse / règles du programme) | `--delay 0.3` |
| Threads de scan | `-t 4` |
| Retries réseau | `--retries 2` |
| **Budget global de requêtes** (garde-fou anti-emballement) | `--max-requests 20000` |
| **Plafond pages d'observation** (stored/stored-dom/postMessage) | `--stored-limit 30` *(défaut)* |
| Ignorer la vérif TLS | `--insecure` |

> **Garde-fous** : les modes « observation de pages » (stored, stored-dom,
> postMessage) testent `points × pages`, ce qui peut exploser sur un gros site.
> `--stored-limit` plafonne les pages observées (défaut 30) et `--max-requests`
> arrête proprement le scan au-delà d'un budget. Sur une cible où le programme
> impose un faible débit, combinez `--delay`, `-t 1` et `--max-requests`.

---

## Rapports

```bash
--format json   # machine (jq)
--format csv    # tableur
--format md     # Markdown prêt pour un writeup HackerOne (+ section PoC curl)
-o rapport.md
```
Chaque finding exploitable embarque une **PoC curl** reproductible et l'info
**CSP** (qui conditionne l'exploitabilité réelle). Les barres de progression
(crawl / réfléchi / DOM / stored / upload / postMessage) s'affichent sur stderr
(elles ne polluent pas le rapport redirigé).

---

## Exemple « tout activé » (cible autorisée)

```bash
python autorecon_xss.py -u "https://app.cible.io/" \
  --wayback --wayback-subdomains --path --headers \
  --stored --stored-dom --upload --postmessage \
  --dom --dom-hash --dom-payloads payloads/mutation-dom.txt \
  --payloads payloads/all.txt \
  --blind "xxxx.oast.pro" \
  --cookies "session=..." --scope 'cible\.io$' \
  --delay 0.3 --threads 4 --format md -o rapport.md --yes
```

---

## Workflow bug bounty recommandé

```bash
# 1. Surface : collecte d'URLs (outils externes)
subfinder -d cible.io -all -silent | httpx -silent > live.txt
cat live.txt | gau --subs > all_urls.txt
cat all_urls.txt | grep '=' | uro > params.txt

# 2. Détection réfléchie + stored sur la surface
python autorecon_xss.py -u "https://cible.io/" --no-crawl -l params.txt \
  --stored --payloads payloads/all.txt \
  --scope 'cible\.io$' --delay 0.3 --format json -o scan.json --yes

# 3. Confirmation DOM sur les points chauds
jq -r '.[]|select(.severity=="high" or .severity=="medium")|.url' scan.json \
  | sort -u > hot.txt
python autorecon_xss.py -u "https://cible.io/" --no-crawl -l hot.txt \
  --dom --dom-hash --scope 'cible\.io$' --delay 0.3 --yes
```

---

## Limites (honnêtes)

- **Aucun scanner ne détecte « tout ».** Prouver l'absence de XSS est
  indécidable. Cet outil maximise la couverture du **détectable automatiquement**.
- Les **chaînes logiques** (CSRF, clobbering, race, RCE) sont manuelles.
- Le blind et les modes navigateur nécessitent respectivement un collecteur et
  Chromium.
- `--postmessage` envoie same-origin : un handler exigeant une origine tierce
  précise peut échapper.
- Respectez les règles de débit du programme (`--delay`, peu de threads).
