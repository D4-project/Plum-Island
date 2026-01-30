"""
This module will parse json results an prepare required data for indexation.

It use a parsing profile description.

hsh:http-header.output
get_http_cookies:http-header.output
get_hosts:http-header.output
get_http_server:http-header.output
get_http_title:http-title.output
get_ssl_info:ssl-cert
get_hosts:ssl-cert.issuer.commonName
get_hosts:ssl-cert.extentions.X509v3_Subject_Alternative_Name

Current problem, is that this syntax should be reversed...
currently it parse headers 3x for ( cookie etc....)
For now far from performance issues anyway.

"""

import re
from pyfaup import Url

DB_CONF = {}

# B -> Body.XXXX Subsearch
# P -> Body.ports.XXXX Per Port Search

default_parsing = [
    "get_hosts:b.hostnames",
    "get_http_server:p.http-headers.output",
    "get_http_cookies:p.http-headers.output",
    "get_http_etag:p.http-headers.output",
    "get_hosts:p.http-headers.output",
    "get_http_title:p.http-title.output",
    "get_ssl_info:p.ssl-cert",
    "get_hosts:p.ssl-cert.issuer.commonName",
    "get_hosts:p.ssl-cert.extensions.X509v3_Subject_Alternative_Name",
    "get_hosts:p.banner.output",
    "get_banner:p.banner.output",
]

# Authorised data harversting methods.
ALLOW = [
    "get_http_cookies",
    "get_hosts",
    "get_http_server",
    "get_http_title",
    "get_http_etag",
    "get_banner",
    "get_ssl_info",
    "hsh",
]

fqdn_regex = re.compile(
    r"""(?:^|[\s(\/<>|@'"=\:])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-_]{2,})+)(?=$|[\?\s#&\/<>'",)])""",
    re.MULTILINE,
)


def insensitive(input_list):
    """
    Put all data in lowercase along the "real one".
    """
    combined = []
    for x in input_list:
        if x:
            combined.append(x)  # original
            combined.append(x.lower())  # lowercase
    return combined


def get_ssl_info(data: dict, target: str, general: bool = False):
    """
    Parse a Nmap script ssl-certs
    """

    ssl_result = get_body(data, target)
    r_issuer = []
    issuers = ssl_result.get("issuer")
    if issuers:
        for issuer in issuers:
            if issuer == "commonName":
                r_issuer = issuers.get("commonName")

    md5sum = ssl_result.get("md5", [])
    sha1sum = ssl_result.get("sha1", [])
    sha256sum = ssl_result.get("sha256", [])
    subject = ssl_result.get("subject")
    if subject:
        subject = subject.get("commonName")
    san = ssl_result.get("extensions")
    if san:
        san = san.get("X509v3 Subject Alternative Name")

    return {
        "x509_issuer": r_issuer,
        "x509_md5": md5sum,
        "x509_sha1": sha1sum,
        "x509_sha256": sha256sum,
        "x509_subject": subject,
        "x509_san": san,
    }


def get_body(data, target):
    """
    Get a Key from the Json with the parsing syntax.
    """
    keys = target.replace("-", "_").replace(" ", "_").split(".")
    current = data
    keys = keys[1:]

    for k in keys:
        k = k.replace("-", "_").replace(" ", "_")
        if isinstance(current, dict):
            norm_map = {key.replace(" ", "_").replace("-", "_"): key for key in current}
            real_key = norm_map.get(k)
            if not real_key:
                return None
            current = current[real_key]
        else:
            return None

    return current


def get_http_cookies(data: dict, target: str):
    """
    Get cookies
    """
    # Parse for http cookies
    body = get_body(data, target)
    http_cookie = []
    if body:
        for line in body.splitlines():
            # I know normally only one server header
            # but just in case, everything is in array
            candidate = line.strip().lower()
            if candidate.startswith("set-cookie:"):
                http_cookie.append(line.split(":", 1)[1].split("=")[0].strip())
    return {"http_cookiename": http_cookie}


def get_http_etag(data: dict, target: str):
    """
    Get etag from http header
    """
    # Parse for http etag
    body = get_body(data, target)
    http_etag = []
    if body:
        for line in body.splitlines():
            # I know normally only one server header
            # but just in case, everything is in array
            candidate = line.strip().lower()
            if candidate.startswith("etag:"):
                http_etag.append(line.split(":", 1)[1].strip())
    return {"http_etag": http_etag}


def get_hosts(data: dict, target: str):
    """
    extract fqdn.
    """
    # Parse for http etag
    body = get_body(data, target)
    hosts, fqdn_hosts, domains, tlds = [], [], [], []
    if body:
        # Extract FQDN using regex if not empty data
        fqdn_hosts_candidates = fqdn_regex.findall(str(body))
        if fqdn_hosts_candidates:
            for host in fqdn_hosts_candidates:
                try:
                    url = Url(f"http://{str.lower(host)}")
                    subdomain = url.subdomain  # Host
                    suffix = url.suffix  # TLD

                    parse = False
                    if suffix:
                        suffix_str = str(url.suffix).lower()  # TLD
                        if DB_CONF["ONLINETLD"]:
                            if suffix.is_known():
                                parse = True
                        else:
                            if suffix_str in DB_CONF["TLDS"]:
                                parse = True

                    if (
                        parse or suffix_str in DB_CONF["TLDADD"]
                    ):  # Validate if TLD is known by a ROOT server
                        fqdn_hosts.append(str.lower(host))
                        if subdomain:
                            hosts.append(str.lower(subdomain))
                        tlds.append(suffix_str)
                        domains.append(str.lower(url.domain))
                except (ValueError, TypeError):
                    pass

    return {"fqdn": fqdn_hosts, "host": hosts, "domain": domains, "tld": tlds}


def get_http_title(data: dict, target: str):
    """
    look for http parsed titles
    """
    body = get_body(data, target)
    http_title = []
    if body:
        http_title = [body]
    return {"http_title": http_title}


def get_banner(data: dict, target: str):
    """
    look for banner text
    """
    body = get_body(data, target)
    banner = []
    if body:
        banner = [body]
    return {"banner": banner}


def get_http_server(data: dict, target: str):
    # Parse http server header
    body = get_body(data, target)
    http_server = []
    if body:
        for line in body.splitlines():
            # I know normally only one server header
            # but just in case, everything is in array
            candidate = line.strip().lower()
            if candidate.startswith("server:"):
                http_server.append(line.split(":", 1)[1].strip())
    return {"http_server": http_server}


def fuse_dicts(d1, d2):
    """
    Merge two dict, and remove empty array value
    """

    fused = {}
    for k in set(d1) | set(d2):
        vals = []
        for v in (d1.get(k), d2.get(k)):
            if v is not None:
                vals += v if isinstance(v, list) else [v]
        vals = list(dict.fromkeys(vals))  # dedup
        if vals:  # keep only non-empty
            fused[k] = vals
    return fused


def parse_json(doc, db_conf_local):

    global DB_CONF
    DB_CONF = db_conf_local

    final_result = {}  # Parsing result array
    for parsing_rule in default_parsing:

        # result = {}  # Parsing result array

        # Check if rule contains a splitter.
        if not ":" in parsing_rule:
            raise TypeError
        action = parsing_rule.split(":")
        target = action[1]
        script_name = target.split(".")[1]
        section = target.split(".")[0]
        action = action[0].lower()
        target = ".".join(target.split(".")[1::])
        # print(f"doing action {action} on {target}")

        # Check if rules contains a legitimate parsing method
        if not action in ALLOW:
            raise TypeError

        parse_result = {}
        # print(f"Looking {target} for section >{section}<")
        if section == "b":
            for script in doc.get("body"):
                if script == script_name:  # If it is in the job list.
                    script = doc.get("body").get(script)
                    parse_result = globals()[action](
                        script, target
                    )  # Call the function given in the action variable.

        elif section == "p":
            for port in doc.get("body").get("ports"):  # for each ports,
                for script in port.get("scripts", []):  # We look at script results
                    if script.get("id") == script_name:  # If it is in the job list.
                        parse_result = globals()[action](
                            script, target
                        )  # Call the function given in the action variable.

        final_result = fuse_dicts(final_result, parse_result)

    ports = []
    for port in doc.get("body").get("ports"):
        ports.append(port.get("portid"))

    uid = doc.get("id")
    ip = doc.get("ip")
    last_seen = doc.get("body").get("endtime")

    final_result = final_result | {
        "uid": uid,
        "ip": ip,
        "last_seen": last_seen,
        "port": ports,
    }

    return final_result
