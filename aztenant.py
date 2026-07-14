#!/usr/bin/env python3
"""
aztenant - resolve an Azure resource to its owning Entra tenant.

Azure resource names are globally unique, so name-matching ("cps-kv-prod must be the CPS one") is
unreliable: different orgs grab similar names. But many Azure services leak their owning **tenant
GUID** in the auth challenge of an *unauthenticated* request. That GUID is ground truth for ownership.
aztenant reads it, so you can confirm a discovered resource really belongs to a target tenant
(attack-surface attribution) instead of guessing by name.

All probes are unauthenticated and read-only: no credentials submitted, no data accessed.

Prior art / related: NetSPI ATEAM (github.com/NetSPI/ATEAM) covers more resource types + tenant→domain
reversal. aztenant's niche: zero-dependency stdlib CLI, concurrent, data-driven & easy to extend.

Quick start:
  aztenant contoso-kv-prod.vault.azure.net
  aztenant -i resources.txt --match contoso.com --only-owned
  aztenant myacct.blob.core.windows.net --proxy http://127.0.0.1:8080 --json

MIT licensed.
"""
from __future__ import annotations
import argparse, concurrent.futures as cf, json, re, ssl, sys, urllib.error, urllib.request

__version__ = "0.1.0"
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

def _tty():
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

def _c(code, text):
    return f"{code}{text}\033[0m" if _tty() else str(text)

_D, _G, _R, _Y = '\033[2m', '\033[32m', '\033[31m', '\033[33m'

# Probe registry -- add a resource type by adding one entry.
# path: appended to https://<host>; headers: extra request headers; follow: follow redirects?
# The tenant GUID is regex-extracted from the WWW-Authenticate + Location response headers.
PROBES: dict[str, dict] = {
    "keyvault":   {"path": "/secrets?api-version=7.4", "headers": {}, "follow": True,
                   "suffixes": [".vault.azure.net"], "status": "stable"},
    "storage":    {"path": "/?restype=account&comp=properties",
                   "headers": {"Authorization": "Bearer x", "x-ms-version": "2021-08-06"},
                   "follow": True,
                   "suffixes": [".blob.core.windows.net", ".file.core.windows.net",
                                ".queue.core.windows.net", ".table.core.windows.net",
                                ".dfs.core.windows.net"], "status": "stable"},
    "appservice": {"path": "/.auth/login/aad", "headers": {}, "follow": False,
                   "suffixes": [".azurewebsites.net"], "status": "stable"},
    # experimental -- verify before trusting; PRs welcome (see ROADMAP)
    "appconfig":  {"path": "/kv?api-version=1.0", "headers": {}, "follow": True,
                   "suffixes": [".azconfig.io"], "status": "experimental"},
    "cognitive":  {"path": "/openai/models?api-version=2023-05-15", "headers": {}, "follow": True,
                   "suffixes": [".openai.azure.com", ".cognitiveservices.azure.com"],
                   "status": "experimental"},
}
_SUFFIX = [(s, t) for t, spec in PROBES.items() for s in spec["suffixes"]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # capture the 3xx instead of following it
        return None


def _opener(proxy, follow):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we probe origins/IPs too; cert identity is irrelevant here
    h = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        h.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if not follow:
        h.append(_NoRedirect())
    return urllib.request.build_opener(*h)


def _fetch(url, headers, proxy, follow, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": f"aztenant/{__version__}", **headers})
    try:
        r = _opener(proxy, follow).open(req, timeout=timeout)
        return r.status, r.headers
    except urllib.error.HTTPError as e:   # 401/403/302-as-error still carry headers
        return e.code, e.headers
    except Exception:
        return None, None


def detect_type(host: str) -> str | None:
    h = host.lower()
    for suffix, t in _SUFFIX:
        if h.endswith(suffix):
            return t
    return None


def resolve_domain_to_tenant(domain, proxy, timeout) -> str | None:
    """domain (contoso.com) → tenant GUID via the public OpenID issuer (unauthenticated)."""
    url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    try:
        r = _opener(proxy, True).open(
            urllib.request.Request(url, headers={"User-Agent": "aztenant"}), timeout=timeout)
        m = GUID.search(json.loads(r.read().decode()).get("issuer", ""))
        return m.group(0).lower() if m else None
    except Exception:
        return None


def reverse_lookup(tenant_guid: str, proxy, timeout, graph_token=None) -> dict:
    """tenant GUID -> metadata. Unauthenticated: confirms existence + region. With graph_token: domains."""
    result = {"tenant": tenant_guid.lower(), "exists": False, "region": None,
              "display_name": None, "default_domain": None, "federation_brand": None}
    url = f"https://login.microsoftonline.com/{tenant_guid}/v2.0/.well-known/openid-configuration"
    try:
        r = _opener(proxy, True).open(
            urllib.request.Request(url, headers={"User-Agent": "aztenant"}), timeout=timeout)
        data = json.loads(r.read().decode())
        if "issuer" in data:
            result["exists"] = True
            result["region"] = data.get("tenant_region_scope")
    except urllib.error.HTTPError:
        return result
    except Exception:
        return result

    if not graph_token or not result["exists"]:
        return result

    graph_url = (f"https://graph.microsoft.com/v1.0/tenantRelationships/"
                 f"findTenantInformationByTenantId(tenantId='{tenant_guid}')")
    try:
        req = urllib.request.Request(graph_url, headers={
            "Authorization": f"Bearer {graph_token}", "User-Agent": "aztenant"})
        r = _opener(proxy, True).open(req, timeout=timeout)
        data = json.loads(r.read().decode())
        result["display_name"] = data.get("displayName")
        result["default_domain"] = data.get("defaultDomainName")
        result["federation_brand"] = data.get("federationBrandName")
    except Exception:
        pass
    return result


def attribute(host: str, forced: str | None, proxy, timeout, retries=1) -> dict:
    rtype = forced or detect_type(host)
    spec = PROBES.get(rtype or "")
    if not spec:
        return {"resource": host, "type": rtype, "status": None, "tenant": None, "reachable": False}
    tenant = code = None
    reachable = False
    for _ in range(retries + 1):
        code, hdrs = _fetch(f"https://{host}{spec['path']}", spec["headers"], proxy, spec["follow"], timeout)
        if hdrs is None:
            continue
        reachable = True
        blob = (hdrs.get("WWW-Authenticate", "") + " " + hdrs.get("Location", "")).strip()
        m = GUID.search(blob)
        tenant = m.group(0).lower() if m else None
        if tenant:
            break
    return {"resource": host, "type": rtype, "status": code, "tenant": tenant, "reachable": reachable}


def _reverse_mode(args):
    guids = args.reverse
    for g in guids:
        if not GUID.fullmatch(g):
            print(f"error: {g!r} is not a valid GUID", file=sys.stderr)
            return 2
    if not args.json:
        print(f"  {'Tenant ID':<38} {'Status':<12} {'Region':<8} Domain")
        print(f"  {_c(_D, chr(9472) * 80)}")
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        results = ex.map(
            lambda g: reverse_lookup(g, args.proxy, args.timeout, args.graph_token), guids)
        for r in results:
            if args.json:
                print(json.dumps(r))
            else:
                if r["exists"]:
                    status = _c(_G, f"{'+ exists':<12}")
                else:
                    status = _c(_R, f"{'- not found':<12}")
                region = f"{(r['region'] or '-'):<8}"
                if r["default_domain"]:
                    domain = r["default_domain"]
                    if r["display_name"]:
                        domain += f" {_c(_D, '(' + r['display_name'] + ')')}"
                else:
                    domain = _c(_D, "(use --graph-token)")
                print(f"  {r['tenant']:<38} {status} {region} {domain}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aztenant", description=__doc__.strip().splitlines()[0])
    ap.add_argument("resources", nargs="*", help="hostnames, or bare names with --suffix")
    ap.add_argument("-i", "--input", help="file with one resource per line ('-' = stdin)")
    ap.add_argument("--type", choices=list(PROBES), help="force resource type (else auto-detect)")
    ap.add_argument("--suffix", help="append this suffix to bare names (e.g. .vault.azure.net)")
    ap.add_argument("--match", metavar="TENANT|DOMAIN", help="tenant GUID or domain to compare against")
    ap.add_argument("--only-owned", action="store_true", help="print only resources matching --match")
    ap.add_argument("--reverse", nargs="+", metavar="GUID",
                    help="reverse mode: resolve tenant GUIDs to metadata/domains")
    ap.add_argument("--graph-token", metavar="TOKEN",
                    help="MS Graph bearer token for tenant domain reversal (--reverse)")
    ap.add_argument("--proxy", help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--threads", type=int, default=10, help="concurrent probes (default 10)")
    ap.add_argument("--retries", type=int, default=1, help="retries on no-tenant (flaky egress)")
    ap.add_argument("--json", action="store_true", help="JSON-lines output")
    ap.add_argument("--version", action="version", version=f"aztenant {__version__}")
    args = ap.parse_args(argv)

    if args.reverse:
        return _reverse_mode(args)

    items = list(args.resources)
    if args.input:
        f = sys.stdin if args.input == "-" else open(args.input)
        items += [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    if args.suffix:
        items = [x if x.endswith(args.suffix) else x + args.suffix for x in items]
    if not items:
        ap.error("no resources given (positional args or -i FILE)")

    target = None
    if args.match:
        target = (args.match.lower() if GUID.fullmatch(args.match)
                  else resolve_domain_to_tenant(args.match, args.proxy, args.timeout))
        if not target:
            print(f"warning: could not resolve --match {args.match!r} to a tenant GUID", file=sys.stderr)

    rc = 1
    n_total = n_match = n_other = n_noaad = n_down = 0
    show = not args.json

    if show:
        if target:
            if GUID.fullmatch(args.match):
                print(f"  {_c(_D, 'target:')} {target}")
            else:
                print(f"  {_c(_D, 'target:')} {target} {_c(_D, '(' + args.match + ')')}")
            print()
        hdr = f"  {'Resource':<48} {'Type':<11} {'Tenant ID':<38}"
        if target:
            hdr += " Match"
        print(hdr)
        print(f"  {_c(_D, chr(9472) * 99)}")

    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        results = ex.map(lambda h: attribute(h, args.type, args.proxy, args.timeout, args.retries), items)
        for r in results:
            n_total += 1
            label = None
            if target and r["tenant"]:
                label = "OWNED" if r["tenant"] == target else "other-tenant"
                if label == "OWNED":
                    rc = 0
                    n_match += 1
                else:
                    n_other += 1
            elif target:
                label = "no-tenant"
                if r["reachable"]:
                    n_noaad += 1
                else:
                    n_down += 1
            if args.only_owned and label != "OWNED":
                continue
            r["match"] = label
            if args.json:
                print(json.dumps(r))
            else:
                if r["tenant"]:
                    t_col = f"{r['tenant']:<38}"
                elif r["reachable"]:
                    t_col = _c(_D, f"{'(no AAD challenge)':<38}")
                else:
                    t_col = _c(_D, f"{'(unreachable)':<38}")
                verdict = ""
                if target:
                    if label == "OWNED":
                        verdict = _c(_G, "+ match")
                    elif label == "other-tenant":
                        verdict = _c(_R, "- other")
                    elif r["reachable"]:
                        verdict = _c(_Y, "? no tenant")
                    else:
                        verdict = _c(_D, "- down")
                print(f"  {r['resource']:<48} {str(r['type'] or '?'):<11} {t_col} {verdict}")

    if show and (n_total > 1 or target):
        parts = [f"{n_total} probed"]
        if target:
            if n_match:
                parts.append(_c(_G, f"{n_match} match"))
            if n_other:
                parts.append(_c(_R, f"{n_other} other"))
            if n_noaad:
                parts.append(_c(_Y, f"{n_noaad} no tenant"))
            if n_down:
                parts.append(_c(_D, f"{n_down} down"))
        print()
        print(f"  {' / '.join(parts)}")

    return rc


if __name__ == "__main__":
    sys.exit(main())
