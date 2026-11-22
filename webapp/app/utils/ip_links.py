"""Choose web links from an observation's indexed tags and port TLS evidence."""


def port_web_scheme(port, tags):
    """Require the normalized proto:http tag; detect TLS on this port only."""
    if "proto:http" not in (tags or []):
        return ""
    service = port.get("service") or {}
    name = str(service.get("name") or "").strip().lower()
    tunnel = str(service.get("tunnel") or "").strip().lower()
    has_tls_evidence = any(
        script.get("id") == "ssl-cert"
        or (
            script.get("id") == "masscan-detection"
            and str(script.get("service") or "").lower() in {"ssl", "tls"}
        )
        for script in port.get("scripts") or []
    )
    if (
        tunnel in {"ssl", "tls"}
        or name in {"https", "https-alt", "ssl", "tls"}
        or name.startswith(("ssl/", "tls/"))
        or has_tls_evidence
    ):
        return "https"
    return "http"
