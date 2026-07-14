# aztenant

**Resolve an Azure resource to its owning Entra tenant via the AAD-challenge GUID leak.**

![demo](demo.gif?v=2)

Azure resource names are *globally unique*, so attributing a discovered resource by name is unreliable:
`contoso-kv-prod.vault.azure.net` might belong to a US school district, not Contoso. But many Azure
services leak their **owning tenant GUID** in the auth challenge of an *unauthenticated* request. That
GUID is ground truth. `aztenant` reads it, so you can confirm which of your name-matched hits actually
belong to the target instead of guessing by name.

- **Zero dependencies.** Python 3 stdlib only. Single file. Drops into any recon box or container.
- **Read-only & unauthenticated.** No credentials submitted, no data accessed; just the auth-challenge header.
- **Concurrent and data-driven.** Add a resource type by adding one dict entry (see `PROBES`).

## Install

```bash
git clone https://github.com/shd-q3/aztenant && cd aztenant
chmod +x aztenant.py            # no pip install needed
```

## Usage

```bash
# one resource (type auto-detected from the hostname suffix)
./aztenant.py contoso-kv-prod.vault.azure.net

# a list, compared against a known tenant (GUID or domain), keep only the owned ones
./aztenant.py -i resources.txt --match contoso.com --only-owned

# through a proxy (e.g. Burp / a recon egress), JSON output
./aztenant.py myacct.blob.core.windows.net --proxy http://127.0.0.1:8080 --json

# bare names + a suffix
printf 'kv-a\nkv-b\n' | ./aztenant.py -i - --suffix .vault.azure.net --match 00000000-0000-0000-0000-000000000000
```

`--match` accepts a tenant GUID *or* a domain (resolved to its GUID via the public OpenID config).
Exit code is `0` if any resource matched `--match`, else `1`.

### Reverse lookup (tenant GUID to domain)

```bash
# confirm tenant exists + get region (unauthenticated)
./aztenant.py --reverse 72f988bf-86f1-41af-91ab-2d7cd011db47

# resolve to actual domain/display name (needs a Graph bearer token)
./aztenant.py --reverse 72f988bf-86f1-41af-91ab-2d7cd011db47 --graph-token eyJ...
```

Without a token the reverse lookup confirms whether a tenant GUID is valid and returns
its region scope (`WW`, `NA`, `EU`, `AS`, etc.). With `--graph-token`, it queries MS Graph's
`findTenantInformationByTenantId` to resolve the default domain, display name, and
federation brand.

## Supported resources

| Type | Suffix | Signal | Status |
|------|--------|--------|--------|
| Key Vault | `.vault.azure.net` | `401 WWW-Authenticate` | stable |
| Storage | `.blob/.file/.queue/.table/.dfs.core.windows.net` | `401 WWW-Authenticate authorization_uri` | stable |
| App Service | `.azurewebsites.net` | `302 Location` (only if Easy Auth/AAD on) | stable |
| App Configuration | `.azconfig.io` | auth challenge | experimental |
| Cognitive / OpenAI | `.openai.azure.com`, `.cognitiveservices.azure.com` | auth challenge | experimental |

## How it works

An unauthenticated request to an AAD-protected Azure endpoint returns an auth challenge that embeds the
owning tenant in a `login.microsoftonline.com/<tenant-guid>/…` URL (in `WWW-Authenticate` or a `Location`
redirect). `aztenant` sends the minimal request per resource type and regex-extracts that GUID. The same
response also tells you the resource is *internet-reachable* (public network access enabled, which is a
hardening signal in its own right).

## Prior art & credit

The tenant-ID-leak technique is documented by **NetSPI** ("Azure Resource Attribution via Tenant ID
Enumeration", 2026), whose **[ATEAM](https://github.com/NetSPI/ATEAM)** ("Azure Tenant Enumeration and
Attribution Module") covers more resource types (SharePoint, Databricks, Azure ML, DevOps, ARM API) and
adds tenant→domain reversal via Microsoft Graph. If you need the most complete coverage today, use ATEAM.
`aztenant` is a zero-dependency stdlib alternative that's easy to hack on. See
[`ROADMAP.md`](ROADMAP.md) for what's next.

## Extending

Add a resource type by adding one entry to `PROBES` in `aztenant.py` (path, headers, follow-redirects,
suffixes). Contributions verifying the experimental probes or adding new leaky services are welcome.

## Legal

For authorised security testing and asset-attribution only. All probes are unauthenticated and read-only,
but you are responsible for having permission to test the resources you point it at.

## License

MIT. See [LICENSE](LICENSE).
