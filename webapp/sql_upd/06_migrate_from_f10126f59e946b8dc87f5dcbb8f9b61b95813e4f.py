import hashlib
import importlib.util
import shutil
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent
DB_PATH = BASE_DIR / "app.db"
CONFIG_PATH = BASE_DIR / "config.py"

TOP_PORTS_TCP = [
    53,
    135,
    3306,
    111,
    587,
    8888,
    199,
    1720,
    548,
    113,
    81,
    6001,
    10000,
    514,
    5060,
    179,
    1026,
    2000,
    8000,
    32768,
    554,
    26,
    1433,
    2001,
    515,
    5666,
    646,
    5000,
    5631,
    631,
    49153,
    8081,
    2049,
    88,
    79,
    5800,
    106,
    1110,
    6000,
    513,
    5357,
    427,
    543,
    544,
    5101,
    144,
    7,
    389,
    8009,
    3128,
    444,
    9999,
    5009,
    7070,
    5190,
    5432,
    1900,
    3986,
    13,
    1029,
    9,
    5051,
    6646,
    1028,
    873,
    1755,
    2717,
    4899,
    9100,
    119,
    37,
]

PACK_SIZE = 15
PROFILE_NAME_PREFIX = "Nmap Top Ports pack"
PROFILE_PRIORITY = 0
SCAN_FREQUENCY_HOURS = 30 * 24
SCAN_CYCLE_MINUTES = SCAN_FREQUENCY_HOURS * 60
PROFILE_NSES = [
    "ssl-cert.nse",
    "tls-alpn.nse",
    "banner.nse",
]

COMMON_NMAP_SCRIPT_DIRS = [
    Path("/usr/share/nmap/scripts"),
    Path("/usr/local/share/nmap/scripts"),
    Path("/opt/homebrew/share/nmap/scripts"),
]
LOCAL_NSE_FALLBACK_DIRS = [
    PROJECT_ROOT / "nse",
    BASE_DIR / "nse",
]


def load_config_module():
    """
    Load the deployed config.py when available.
    """
    try:
        spec = importlib.util.spec_from_file_location("plum_config", CONFIG_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


CONFIG_MODULE = load_config_module()


def load_upload_folder():
    """
    Resolve the upload folder used by Flask-AppBuilder file storage.
    """
    if CONFIG_MODULE is not None and getattr(CONFIG_MODULE, "UPLOAD_FOLDER", None):
        return Path(getattr(CONFIG_MODULE, "UPLOAD_FOLDER"))
    return BASE_DIR / "app" / "static" / "uploads"


def load_nmap_script_dirs():
    """
    Resolve configured and common Nmap script directories.
    """
    directories = []
    configured_dir = getattr(CONFIG_MODULE, "NMAP_SCRIPTS_DIR", None) if CONFIG_MODULE else None
    if configured_dir:
        directories.append(Path(configured_dir))
    directories.extend(COMMON_NMAP_SCRIPT_DIRS)

    unique_dirs = []
    seen = set()
    for directory in directories + LOCAL_NSE_FALLBACK_DIRS:
        resolved = directory.expanduser()
        if resolved not in seen:
            seen.add(resolved)
            unique_dirs.append(resolved)
    return unique_dirs


def normalize_nse_name(name):
    """
    Normalize NSE script names to actual .nse filenames.
    """
    base_name = Path(str(name or "").strip()).name
    if not base_name:
        return None
    if not base_name.endswith(".nse"):
        base_name = f"{base_name}.nse"
    return base_name


def find_nmap_script(script_name):
    """
    Resolve an NSE script path from local Nmap or bundled scripts.
    """
    normalized_name = normalize_nse_name(script_name)
    if not normalized_name:
        return None
    for script_dir in load_nmap_script_dirs():
        candidate = script_dir / normalized_name
        if candidate.is_file():
            return candidate
    return None


def sha256sum(path):
    """
    Compute the SHA-256 of a file.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def table_exists(cursor, table_name):
    """
    Check whether a sqlite table exists.
    """
    cursor.execute(
        """
        SELECT 1
          FROM sqlite_master
         WHERE type = 'table'
           AND name = ?
         LIMIT 1
        """,
        (table_name,),
    )
    return cursor.fetchone() is not None


def ensure_tcp_proto(cursor):
    """
    Ensure the TCP protocol row exists and return its id.
    """
    cursor.execute("SELECT id FROM protos WHERE LOWER(value) = 'tcp' LIMIT 1")
    row = cursor.fetchone()
    if row:
        return row[0]

    cursor.execute(
        "INSERT INTO protos (value, name) VALUES (?, ?)",
        ("TCP", "Transmission Control Protocol"),
    )
    return cursor.lastrowid


def ensure_tcp_port(cursor, tcp_proto_id, port):
    """
    Ensure one TCP port row exists and return its id.
    """
    proto_to_port = f"{port}:{tcp_proto_id}"
    cursor.execute("SELECT id FROM ports WHERE proto_to_port = ? LIMIT 1", (proto_to_port,))
    row = cursor.fetchone()
    if row:
        return row[0]

    cursor.execute(
        """
        INSERT INTO ports (value, name, proto_id, proto_to_port)
        VALUES (?, ?, ?, ?)
        """,
        (
            port,
            f"Nmap Top Ports {port}/TCP",
            tcp_proto_id,
            proto_to_port,
        ),
    )
    return cursor.lastrowid


def ensure_nse(cursor, upload_folder, script_name):
    """
    Ensure one NSE script row exists and return its id.
    """
    normalized_name = normalize_nse_name(script_name)
    if not normalized_name:
        raise RuntimeError(f"Invalid NSE script name: {script_name}")

    cursor.execute("SELECT id FROM nses WHERE name = ? LIMIT 1", (normalized_name,))
    row = cursor.fetchone()
    if row:
        return row[0]

    script_path = find_nmap_script(normalized_name)
    if script_path is None:
        raise FileNotFoundError(f"Unable to find required NSE script: {normalized_name}")

    file_hash = sha256sum(script_path)
    cursor.execute("SELECT id FROM nses WHERE hash = ? LIMIT 1", (file_hash,))
    row = cursor.fetchone()
    if row:
        return row[0]

    upload_folder.mkdir(parents=True, exist_ok=True)
    stored_file_name = f"top_ports_packs__{normalized_name}"
    shutil.copyfile(script_path, upload_folder / stored_file_name)

    cursor.execute(
        """
        INSERT INTO nses (name, hash, filebody)
        VALUES (?, ?, ?)
        """,
        (normalized_name, file_hash, stored_file_name),
    )
    return cursor.lastrowid


def chunks(values, size):
    """
    Yield values in fixed-size chunks.
    """
    for index in range(0, len(values), size):
        yield values[index : index + size]


def ensure_scan_profile(cursor, pack_number):
    """
    Ensure one top-port pack scan profile exists and return its id.
    """
    profile_name = f"{PROFILE_NAME_PREFIX} {pack_number}"
    cursor.execute("SELECT id FROM scanprofiles WHERE name = ? LIMIT 1", (profile_name,))
    row = cursor.fetchone()
    if row:
        profile_id = row[0]
        cursor.execute(
            """
            UPDATE scanprofiles
               SET apply_to_all = 1,
                   priority = ?,
                   scan_cycle_minutes = ?
             WHERE id = ?
            """,
            (PROFILE_PRIORITY, SCAN_CYCLE_MINUTES, profile_id),
        )
        return profile_id

    cursor.execute(
        """
        INSERT INTO scanprofiles (name, apply_to_all, priority, scan_cycle_minutes)
        VALUES (?, ?, ?, ?)
        """,
        (profile_name, 1, PROFILE_PRIORITY, SCAN_CYCLE_MINUTES),
    )
    return cursor.lastrowid


def replace_profile_ports(cursor, profile_id, port_ids):
    """
    Replace the port associations for one managed profile.
    """
    cursor.execute(
        "DELETE FROM scanprofiles_ports_assoc WHERE scanprofile_id = ?",
        (profile_id,),
    )
    for port_id in port_ids:
        cursor.execute(
            """
            INSERT OR IGNORE INTO scanprofiles_ports_assoc (scanprofile_id, port_id)
            VALUES (?, ?)
            """,
            (profile_id, port_id),
        )


def replace_profile_nses(cursor, profile_id, nse_ids):
    """
    Replace the NSE associations for one managed profile.
    """
    cursor.execute(
        "DELETE FROM scanprofiles_nses_assoc WHERE scanprofile_id = ?",
        (profile_id,),
    )
    for nse_id in nse_ids:
        cursor.execute(
            """
            INSERT OR IGNORE INTO scanprofiles_nses_assoc (scanprofile_id, nses_id)
            VALUES (?, ?)
            """,
            (profile_id, nse_id),
        )


def ensure_all_scan_states(cursor, profile_ids):
    """
    Ensure All Scan profiles have runtime state rows for active targets.
    """
    if not table_exists(cursor, "target_scan_states"):
        return

    for profile_id in profile_ids:
        cursor.execute(
            """
            INSERT OR IGNORE INTO target_scan_states (target_id, scanprofile_id, working)
            SELECT id, ?, 0
              FROM targets
             WHERE active = 1
            """,
            (profile_id,),
        )


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

tcp_proto_id = ensure_tcp_proto(cursor)
upload_folder = load_upload_folder()
nse_ids = [ensure_nse(cursor, upload_folder, script_name) for script_name in PROFILE_NSES]

created_profile_ids = []
for pack_number, port_pack in enumerate(chunks(TOP_PORTS_TCP, PACK_SIZE), start=1):
    profile_id = ensure_scan_profile(cursor, pack_number)
    port_ids = [ensure_tcp_port(cursor, tcp_proto_id, port) for port in port_pack]
    replace_profile_ports(cursor, profile_id, port_ids)
    replace_profile_nses(cursor, profile_id, nse_ids)
    created_profile_ids.append(profile_id)

ensure_all_scan_states(cursor, created_profile_ids)

conn.commit()
conn.close()
