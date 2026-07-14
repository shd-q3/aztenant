# aztenant roadmap

Where we are (v0.1): unauthenticated tenant-GUID attribution for Key Vault / Storage / App Service
(stable) + App Config / Cognitive (experimental), concurrent, zero-dep, `--match` by GUID or domain.

## Near-term (parity)
- [ ] **Verify + promote the experimental probes** (App Config, Cognitive/OpenAI) with real evidence;
      add Service Bus (`.servicebus.windows.net`), Event Grid, SignalR, Static Web Apps, API Mgmt (`.azure-api.net`),
      Container Apps, Redis, Cosmos, SQL (`.database.windows.net`).
- [x] **Tenant → owner-domain reversal.** `--reverse GUID [GUID...]` confirms existence + region via
      unauthenticated OpenID config; `--graph-token` adds domain/display-name via Graph
      `findTenantInformationByTenantId`.
- [ ] **SharePoint / DevOps** attribution (ATEAM covers these; match its surface).

## Discovery integration (beyond attribution)
- [ ] **`--from-keyword <kw>` mode**: permute a keyword across suffixes → resolve via DNS/DoH → attribute,
      in one pass (combines `cloud_enum`-style discovery with ownership proof).
- [ ] Read resource lists from `cloud_enum` / `MicroBurst` / `subfinder` output directly.

## Quality / release
- [ ] CSV + NDJSON + markdown-table output; `--fields` selector.
- [ ] Rate-limit / backoff flags for flaky egress; per-request jitter.
- [ ] Cache tenant→domain lookups.
- [ ] `pipx`-installable `pyproject.toml` (keep the single-file zero-dep path too).
- [ ] GitHub Actions CI running the offline tests; publish to PyPI.
- [ ] More offline tests (probe-registry integrity, header-parsing fixtures captured from real responses).

## Stretch / differentiators
- [ ] **Cross-cloud**: GCP (`appspot.com`, `run.app`, `firebaseio.com`) + AWS (S3 region/owner hints) attribution.
- [ ] **Reachability/posture report**: flag resources with public network access on (the challenge already proves it).
- [ ] **Confidence scoring** when the tenant can't be read (CNAME-to-known-infra, cert SAN, custom-domain binding).
