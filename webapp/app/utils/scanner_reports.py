"""Expose observed Masscan HTTP responses through the existing NSE fields."""

import re
from copy import deepcopy


def report_engine(document):
    """Scanner metadata belongs to the raw report body; legacy reports are Nmap."""
    body = document.get("body") or {}
    value = body.get("engine") if isinstance(body, dict) else None
    return (
        "masscan"
        if isinstance(value, str) and value.strip().lower() == "masscan"
        else "nmap"
    )


def display_scripts(port):
    """Show Masscan observations through the same NSE blocks as Nmap reports."""
    return [
        script
        for script in normalize_masscan_port(port).get("scripts") or []
        if script.get("id") != "masscan-detection"
    ]


_HTTP_STATUS = re.compile(r"^HTTP/\d(?:\.\d)? [1-5]\d{2}(?:[ \t]|$)")
_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+:")
_LINE_ESCAPE = re.compile(r"\\(?:x)?(0d|0a|09)", re.IGNORECASE)


def http_headers_output(output):
    """Extract actual response headers and stop before any HTTP body."""
    text = _LINE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), output)
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if not lines or not _HTTP_STATUS.match(lines[0]):
        return None
    headers = []
    for line in lines[1:]:
        if not line:
            break
        if _HEADER.match(line):
            headers.append(line)
        elif line.startswith((" ", "\t")) and headers:
            headers[-1] += " " + line.strip()
        else:
            return None
    return "\n" + "\n".join(headers) if headers else None


def normalize_masscan_port(port):
    """Add NSE-compatible banner and HTTP fields without replacing observations."""
    result = deepcopy(port)
    scripts = result.get("scripts") or []
    existing = {script.get("id") for script in scripts}
    banners = []
    responses = []
    for script in scripts:
        if script.get("id") != "masscan-detection":
            continue
        output = script.get("output")
        if not isinstance(output, str) or not output:
            continue
        if output not in banners:
            banners.append(output)
        headers = http_headers_output(output)
        if headers is not None and headers not in responses:
            responses.append(headers)
    if banners and "banner" not in existing:
        scripts.append({"id": "banner", "output": "\n".join(banners)})
    if responses and "http-headers" not in existing:
        scripts.append({"id": "http-headers", "output": "\n".join(responses)})
    if banners:
        result["scripts"] = sorted(
            scripts,
            key=lambda script: (
                script.get("id", ""),
                script.get("service", ""),
                script.get("output", ""),
            ),
        )
    return result
