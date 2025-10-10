import os
import json


def insensitive(input_list):
    combined = []
    for x in input_list:
        if x:
            combined.append(x)  # original
            combined.append(x.lower())  # lowercase
    return combined


def parse_http_headers(headers):
    # print(headers)
    # Set-Cookie: acSamlv2Error=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure
    http_cookies = []
    http_servers = []

    for line in headers.splitlines():
        # I know normally only one server header.
        if line.strip().lower().startswith("server:"):
            http_servers.append(line.split(":", 1)[1].strip())
        if line.strip().lower().startswith("set-cookie:"):
            http_cookies.append(line.split(":", 1)[1].split("=")[0].strip())
    return {"http_servers": http_servers, "http_cookies": http_cookies}


def parse_json(doc):
    uid = doc.get("id")
    ip = doc.get("ip")

    ports = []
    http_servers = []
    http_titles = []
    http_cookies = []
    last_seen = doc.get("body").get("endtime")
    for port in doc.get("body").get("ports"):
        ports.append(port.get("portid"))
        for script in port.get("scripts", []):
            if script.get("id") == "http-title":
                http_titles.append(script.get("title", ""))
            if script.get("id") == "http-headers":
                parsed_headers = parse_http_headers(script.get("output", {}))
                http_servers.extend(parsed_headers.get("http_servers"))
                http_cookies.extend(parsed_headers.get("http_cookies"))

            if script.get("id") == "ssl-cert":
                pass
                # parse_cerfificate(script.get("output"))

    # deduplicate things
    http_servers = list(set(insensitive(http_servers)))
    http_titles = list(set(insensitive(http_titles)))
    http_cookies = list(set(insensitive(http_cookies)))
    """
    print(
        f"IP: {ip}, uid{uid}, last_seen{last_seen}, Ports {ports}, http_server {http_servers},cookies {http_cookies},  http_titles {http_titles}, ssl_commonnames {ssl_commonnames}"
    )
    """
    # Construct the object for indexing.
    object_to_index = {
        "uid": uid,
        "ip": ip,
        "favicon_hashes": [],
        "http_servers": http_servers,
        "http_cookies": http_cookies,
        "http_titles": http_titles,
        "ports": ports,
        "last_seen": last_seen,
    }
    return object_to_index
