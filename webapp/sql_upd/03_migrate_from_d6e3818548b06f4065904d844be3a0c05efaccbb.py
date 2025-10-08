
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


'''

conn = sqlite3.connect('../app.db')
cursor = conn.cursor()
# Add the job_creation column
cursor.execute("ALTER TABLE jobs ADD COLUMN priority INTEGER;")
# push "now" to existing row job.
cursor.execute("UPDATE jobs SET priority = 0;")

# set timestamp for existing rows
conn.commit()
conn.close()
