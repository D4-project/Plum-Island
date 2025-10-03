
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
        PRIMARY KEY (id), 
        UNIQUE (uid)
);
'''

conn = sqlite3.connect('../app.db')
cursor = conn.cursor()
cursor.execute("ALTER TABLE jobs ADD COLUMN exported BOOLEAN DEFAULT 0")
conn.commit()
conn.close()
