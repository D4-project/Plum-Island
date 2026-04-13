import hashlib
import importlib.util
import shutil
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent
DB_PATH = BASE_DIR / "app.db"
CONFIG_PATH = BASE_DIR / "config.py"
DEFAULT_NMAP_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3389, 8080, 8443]
DEFAULT_NMAP_NSE = [
    "http-headers.nse",
    "http-favicon.nse",
    "http-title.nse",
    "http-security-headers.nse",
    "ssl-cert.nse",
    "ssh-hostkey.nse",
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


def load_scan_delay_hours():
    """
    Read SCAN_DELAY from the deployed config.py when available.
    """
    if CONFIG_MODULE is None:
        return 12
    try:
        return int(getattr(CONFIG_MODULE, "SCAN_DELAY", 12))
    except Exception:
        return 12


def load_legacy_nmap_ports():
    """
    Read the legacy global port list from config.py when available.
    """
    ports = getattr(CONFIG_MODULE, "NMAP_PORTS", DEFAULT_NMAP_PORTS) if CONFIG_MODULE else DEFAULT_NMAP_PORTS
    normalized = []
    for port in ports or []:
        try:
            port_value = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= port_value <= 65535 and port_value not in normalized:
            normalized.append(port_value)
    return normalized or list(DEFAULT_NMAP_PORTS)


def normalize_nse_name(name):
    """
    Normalize legacy script names to actual .nse filenames.
    """
    base_name = Path(str(name or "").strip()).name
    if not base_name:
        return None
    if not base_name.endswith(".nse"):
        base_name = f"{base_name}.nse"
    return base_name


def load_legacy_nmap_nses():
    """
    Read the legacy global NSE list from config.py when available.
    """
    scripts = getattr(CONFIG_MODULE, "NMAP_NSE", DEFAULT_NMAP_NSE) if CONFIG_MODULE else DEFAULT_NMAP_NSE
    normalized = []
    for script_name in scripts or []:
        normalized_name = normalize_nse_name(script_name)
        if normalized_name and normalized_name not in normalized:
            normalized.append(normalized_name)
    return normalized


def load_upload_folder():
    """
    Resolve the upload folder used by Flask-AppBuilder file storage.
    """
    if CONFIG_MODULE is not None and getattr(CONFIG_MODULE, "UPLOAD_FOLDER", None):
        return Path(getattr(CONFIG_MODULE, "UPLOAD_FOLDER"))
    return BASE_DIR / "app" / "static" / "uploads"


def load_nmap_script_dirs():
    """
    Resolve the local Nmap script directories to import legacy NSE scripts.
    """
    directories = []
    configured_dir = getattr(CONFIG_MODULE, "NMAP_SCRIPTS_DIR", None) if CONFIG_MODULE else None
    if configured_dir:
        directories.append(Path(configured_dir))
    directories.extend(COMMON_NMAP_SCRIPT_DIRS)
    unique_dirs = []
    seen = set()
    for directory in directories:
        resolved = directory.expanduser()
        if resolved not in seen:
            seen.add(resolved)
            unique_dirs.append(resolved)
    return unique_dirs


def load_local_nse_fallback_dirs():
    """
    Resolve local repository fallback directories for bundled NSE scripts.
    """
    unique_dirs = []
    seen = set()
    for directory in LOCAL_NSE_FALLBACK_DIRS:
        resolved = directory.expanduser()
        if resolved not in seen:
            seen.add(resolved)
            unique_dirs.append(resolved)
    return unique_dirs


def find_nmap_script(script_name):
    """
    Resolve an NSE script path from the local Nmap distribution.
    """
    normalized_name = normalize_nse_name(script_name)
    if not normalized_name:
        return None
    for script_dir in load_nmap_script_dirs():
        candidate = script_dir / normalized_name
        if candidate.is_file():
            return candidate
    for script_dir in load_local_nse_fallback_dirs():
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


def column_exists(cursor, table_name, column_name):
    """
    Check whether a column exists on a sqlite table.
    """
    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in cursor.fetchall())


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


def ensure_default_profile(cursor, scan_cycle_minutes):
    """
    Ensure a legacy-compatible default profile exists.
    """
    cursor.execute(
        """
        SELECT id
          FROM scanprofiles
         WHERE LOWER(name) IN ('default', 'defaut')
         ORDER BY id ASC
         LIMIT 1
        """
    )
    row = cursor.fetchone()
    if row:
        profile_id = row[0]
        cursor.execute(
            """
            UPDATE scanprofiles
               SET apply_to_all = 1,
                   scan_cycle_minutes = CASE
                       WHEN scan_cycle_minutes IS NULL OR scan_cycle_minutes <= 0
                       THEN ?
                       ELSE scan_cycle_minutes
                   END
             WHERE id = ?
            """,
            (scan_cycle_minutes, profile_id),
        )
        return profile_id

    cursor.execute(
        """
        INSERT INTO scanprofiles (name, apply_to_all, priority, scan_cycle_minutes)
        VALUES (?, ?, ?, ?)
        """,
        ("default", 1, 0, scan_cycle_minutes),
    )
    return cursor.lastrowid


def ensure_profile_ports(cursor, profile_id, ports):
    """
    Ensure the migrated default profile is linked to the legacy global port set.
    """
    tcp_proto_id = ensure_tcp_proto(cursor)
    associated_ports = []

    for port in ports:
        proto_to_port = f"{port}:{tcp_proto_id}"
        cursor.execute(
            "SELECT id FROM ports WHERE proto_to_port = ? LIMIT 1",
            (proto_to_port,),
        )
        row = cursor.fetchone()
        if row:
            port_id = row[0]
        else:
            cursor.execute(
                """
                INSERT INTO ports (value, name, proto_id, proto_to_port)
                VALUES (?, ?, ?, ?)
                """,
                (
                    port,
                    f"Legacy global port {port}/TCP",
                    tcp_proto_id,
                    proto_to_port,
                ),
            )
            port_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT OR IGNORE INTO scanprofiles_ports_assoc (scanprofile_id, port_id)
            VALUES (?, ?)
            """,
            (profile_id, port_id),
        )
        associated_ports.append(str(port))

    return ",".join(associated_ports)


def ensure_profile_nses(cursor, profile_id, upload_folder, script_names):
    """
    Import legacy global NSE scripts into the database and associate them to the
    migrated default profile.
    """
    upload_folder.mkdir(parents=True, exist_ok=True)
    associated_names = []

    for script_name in script_names:
        normalized_name = normalize_nse_name(script_name)
        if not normalized_name:
            continue

        cursor.execute("SELECT id, name FROM nses WHERE name = ? LIMIT 1", (normalized_name,))
        row = cursor.fetchone()
        if row:
            nse_id = row[0]
            stored_name = row[1]
        else:
            script_path = find_nmap_script(normalized_name)
            if script_path is None:
                print(f"[WARN] Unable to find local Nmap script for {normalized_name}, skipping.")
                continue

            file_hash = sha256sum(script_path)
            cursor.execute("SELECT id, name FROM nses WHERE hash = ? LIMIT 1", (file_hash,))
            row = cursor.fetchone()
            if row:
                nse_id = row[0]
                stored_name = row[1]
            else:
                stored_file_name = f"legacy_migrated__{normalized_name}"
                shutil.copyfile(script_path, upload_folder / stored_file_name)
                cursor.execute(
                    """
                    INSERT INTO nses (name, hash, filebody)
                    VALUES (?, ?, ?)
                    """,
                    (normalized_name, file_hash, stored_file_name),
                )
                nse_id = cursor.lastrowid
                stored_name = normalized_name

        cursor.execute(
            """
            INSERT OR IGNORE INTO scanprofiles_nses_assoc (scanprofile_id, nses_id)
            VALUES (?, ?)
            """,
            (profile_id, nse_id),
        )
        if stored_name not in associated_names:
            associated_names.append(stored_name)

    return ",".join(associated_names)


def backfill_legacy_jobs(cursor, default_profile_id, scan_ports_csv, scan_nses_csv):
    """
    Populate the new job columns for finished pre-migration jobs so job history
    remains coherent after the code upgrade.
    """
    cursor.execute(
        """
        UPDATE jobs
           SET scanprofile_id = COALESCE(scanprofile_id, ?),
               scan_ports = COALESCE(scan_ports, ?),
               scan_nses = COALESCE(scan_nses, ?)
         WHERE scanprofile_id IS NULL
            OR scan_ports IS NULL
            OR scan_nses IS NULL
        """,
        (default_profile_id, scan_ports_csv, scan_nses_csv),
    )


def purge_unfinished_jobs(cursor):
    """
    Drop every waiting or running job so the scheduler can rebuild clean queues.
    """
    cursor.execute(
        """
        DELETE FROM jobs_targets_assoc
         WHERE job_id IN (
            SELECT id
              FROM jobs
             WHERE finished = 0
         )
        """
    )
    cursor.execute("DELETE FROM jobs WHERE finished = 0")
    cursor.execute("UPDATE bots SET running = 0")


def reset_scheduler_runtime_state(cursor):
    """
    Reset scheduler runtime flags so every target/profile can be scheduled again.
    """
    cursor.execute(
        """
        UPDATE target_scan_states
           SET working = 0,
               last_previous_scan = COALESCE(last_scan, last_previous_scan),
               last_scan = NULL
        """
    )
    cursor.execute("UPDATE targets SET working = 0")


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

default_scan_cycle_minutes = load_scan_delay_hours() * 60
legacy_ports = load_legacy_nmap_ports()
legacy_nses = load_legacy_nmap_nses()
upload_folder = load_upload_folder()

if not column_exists(cursor, "scanprofiles", "scan_cycle_minutes"):
    cursor.execute("ALTER TABLE scanprofiles ADD COLUMN scan_cycle_minutes INTEGER;")

if not column_exists(cursor, "jobs", "scanprofile_id"):
    cursor.execute("ALTER TABLE jobs ADD COLUMN scanprofile_id INTEGER;")

if not column_exists(cursor, "jobs", "scan_ports"):
    cursor.execute("ALTER TABLE jobs ADD COLUMN scan_ports TEXT;")

if not column_exists(cursor, "jobs", "scan_nses"):
    cursor.execute("ALTER TABLE jobs ADD COLUMN scan_nses TEXT;")

cursor.execute(
    """
    UPDATE scanprofiles
       SET scan_cycle_minutes = ?
     WHERE scan_cycle_minutes IS NULL
        OR scan_cycle_minutes <= 0
    """,
    (default_scan_cycle_minutes,),
)

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS target_scan_states (
        id INTEGER NOT NULL PRIMARY KEY,
        target_id INTEGER NOT NULL,
        scanprofile_id INTEGER NOT NULL,
        working BOOLEAN DEFAULT 0,
        last_scan DATETIME,
        last_previous_scan DATETIME,
        FOREIGN KEY(target_id) REFERENCES targets(id),
        FOREIGN KEY(scanprofile_id) REFERENCES scanprofiles(id)
    );
    """
)

cursor.execute(
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_target_scan_states_target_profile
        ON target_scan_states(target_id, scanprofile_id);
    """
)

default_profile_id = ensure_default_profile(cursor, default_scan_cycle_minutes)
scan_ports_csv = ensure_profile_ports(cursor, default_profile_id, legacy_ports)
scan_nses_csv = ensure_profile_nses(cursor, default_profile_id, upload_folder, legacy_nses)
purge_unfinished_jobs(cursor)
backfill_legacy_jobs(cursor, default_profile_id, scan_ports_csv, scan_nses_csv)

cursor.execute(
    """
    INSERT OR IGNORE INTO target_scan_states (target_id, scanprofile_id, working)
    SELECT target_id, scanprofile_id, 0
      FROM scanprofiles_targets_assoc
    """
)
reset_scheduler_runtime_state(cursor)

conn.commit()
conn.close()
