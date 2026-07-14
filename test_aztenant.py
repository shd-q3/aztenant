"""Offline unit tests for aztenant (no network). Run: python3 -m pytest -q  (or python3 test_aztenant.py)"""
import aztenant as az


def test_detect_type():
    assert az.detect_type("x.vault.azure.net") == "keyvault"
    assert az.detect_type("x.blob.core.windows.net") == "storage"
    assert az.detect_type("x.dfs.core.windows.net") == "storage"
    assert az.detect_type("x.azurewebsites.net") == "appservice"
    assert az.detect_type("x.azconfig.io") == "appconfig"
    assert az.detect_type("x.openai.azure.com") == "cognitive"
    assert az.detect_type("example.com") is None


def test_guid_extraction_from_challenge():
    g = "00dd0d1d-d7e6-4338-ac51-565339c7088c"
    header = f'Bearer authorization_uri=https://login.microsoftonline.com/{g}/oauth2/authorize'
    m = az.GUID.search(header)
    assert m and m.group(0).lower() == g


def test_probe_registry_integrity():
    # every probe must have the required keys and at least one suffix
    for t, spec in az.PROBES.items():
        assert {"path", "headers", "follow", "suffixes", "status"} <= spec.keys(), t
        assert spec["suffixes"], t
        assert spec["status"] in ("stable", "experimental"), t
    # suffix map has no dupes pointing at different types
    seen = {}
    for suffix, t in az._SUFFIX:
        assert suffix not in seen, f"duplicate suffix {suffix}"
        seen[suffix] = t


def test_guid_fullmatch_vs_domain():
    assert az.GUID.fullmatch("00dd0d1d-d7e6-4338-ac51-565339c7088c")
    assert not az.GUID.fullmatch("contoso.com")


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
    sys.exit(0)
