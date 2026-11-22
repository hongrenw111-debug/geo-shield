from geo_shield.retrieval import fetch_page


def test_ssrf_blocks_cgnat_and_private_ips() -> None:
    for blocked in (
        "http://127.0.0.1:8080/secret",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://100.64.0.1/status",
    ):
        rep = fetch_page(blocked, timeout=0.5)
        assert rep.ok is False
        assert "Blocked" in rep.error
