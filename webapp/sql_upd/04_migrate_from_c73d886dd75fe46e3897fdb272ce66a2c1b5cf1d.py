
import sqlite3

'''
Source Schema

CREATE TABLE targets (
        id INTEGER NOT NULL, 
        value VARCHAR(45) NOT NULL, 
        description VARCHAR(256), 
        active BOOLEAN, 
        working BOOLEAN, 
        last_scan DATETIME, last_previous_scan DATETIME, 
        PRIMARY KEY (id), 
        UNIQUE (value)
);


'''
conn = sqlite3.connect('../app.db')
cursor = conn.cursor()
# Add the job_creation column
cursor.execute("ALTER TABLE targets ADD COLUMN priority INTEGER;")
# push "now" to existing row job.
cursor.execute("UPDATE jobs SET priority = 1;")
cursor.execute("ALTER TABLE targets ADD COLUMN as_bgp INTEGER;")
cursor.execute("ALTER TABLE targets ADD COLUMN as_description VARCHAR(256);")
cursor.execute("ALTER TABLE targets ADD COLUMN as_country VARCHAR(2);")


conn.commit()

try:
    cursor.execute('ALTER TABLE "Nses" RENAME TO lw_nses;')
    cursor.execute('ALTER TABLE "Ports" RENAME TO lw_ports;')
    cursor.execute('ALTER TABLE "Protos" RENAME TO lw_protos;')
    cursor.execute('ALTER TABLE "ScanProfiles" RENAME TO lw_scan_profiles;')
    conn.commit()

    cursor.execute('ALTER TABLE lw_nses RENAME TO nses;')
    cursor.execute('ALTER TABLE lw_ports RENAME TO ports;')
    cursor.execute('ALTER TABLE lw_protos RENAME TO protos;')
    cursor.execute('ALTER TABLE lw_scan_profiles RENAME TO scanprofiles;')
    conn.commit()
except Exception as e:
    conn.rollback()
    print("ALTER failed:", e)

cursor.execute("ALTER TABLE nses ADD COLUMN filebody TEXT NOT NULL DEFAULT '';")
cursor.execute("ALTER TABLE nses DROP COLUMN body;")

# Add the job_creation column
cursor.execute("ALTER TABLE scanprofiles ADD COLUMN priority INTEGER;")
# push "now" to existing row job.
cursor.execute("UPDATE scanprofiles SET priority = 1;")
# set timestamp for existing rows
conn.commit()
conn.close()
