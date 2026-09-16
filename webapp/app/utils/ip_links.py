"""Choose web links from an observation's indexed tags and port TLS evidence."""


def port_web_scheme(port, tags):
    """Require the normalized proto:http tag; detect TLS on this port only."""
    if "proto:http" not in (tags or []):
        return ""
    service = port.get("service") or {}
    name = str(service.get("name") or "").strip().lower()
    tunnel = str(service.get("tunnel") or "").strip().lower()
    has_certificate = any(
        script.get("id") == "ssl-cert" for script in port.get("scripts") or []
    )
    if (
        tunnel in {"ssl", "tls"}
        or name in {"https", "https-alt", "ssl", "tls"}
        or name.startswith(("ssl/", "tls/"))
        or has_certificate
    ):
        return "https"
    return "http"
