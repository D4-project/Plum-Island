
import sqlite3

'''
Source Schema

CREATE TABLE jobs (
        id INTEGER NOT NULL, 
        uid VARCHAR(36) NOT NULL, 
        job VARCHAR NOT NULL, 
        bot_id INTEGER, 
        active BOOLEAN, 
        finished BOOLEAN, 
        job_end DATETIME, 
        job_start DATETIME, 
        exported BOOLEAN DEFAULT 0, 
        PRIMARY KEY (id), 
        UNIQUE (uid)
);

CREATE TABLE targets (
        id INTEGER NOT NULL, 
        value VARCHAR(45) NOT NULL, 
        description VARCHAR(256), 
        active BOOLEAN, 
        working BOOLEAN, 
        last_scan DATETIME, 
        PRIMARY KEY (id), 
        UNIQUE (value)
);

'''

conn = sqlite3.connect('../app.db')
cursor = conn.cursor()
# Add the job_creation column
cursor.execute("ALTER TABLE jobs ADD COLUMN job_creation DATETIME;")
cursor.execute("ALTER TABLE targets ADD COLUMN last_previous_scan DATETIME;")
# push "now" to existing row job.
cursor.execute("UPDATE jobs SET job_creation = CURRENT_TIMESTAMP;")

# set timestamp for existing rows
conn.commit()
conn.close()
