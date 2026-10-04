import sqlite3
from pathlib import Path
DB_PATH=Path(__file__).resolve().parent.parent/'monitor.db'
def get_connection():
 c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row; return c
def init_db():
 c=get_connection(); c.executescript('''CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL,hostname TEXT NOT NULL,cpu_percent REAL NOT NULL,memory_percent REAL NOT NULL,load1 REAL,disk_used_percent REAL); CREATE TABLE IF NOT EXISTS tasks(task_id TEXT PRIMARY KEY,category TEXT NOT NULL,name TEXT NOT NULL,command TEXT,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,status TEXT NOT NULL,metadata TEXT DEFAULT '{}'); CREATE TABLE IF NOT EXISTS task_samples(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT NOT NULL,sample_id INTEGER NOT NULL,timestamp TEXT NOT NULL,pid INTEGER,status TEXT,cpu_percent REAL DEFAULT 0,memory_percent REAL DEFAULT 0,rss_bytes INTEGER DEFAULT 0); CREATE INDEX IF NOT EXISTS idx_task_samples_task ON task_samples(task_id);'''); c.commit(); c.close()
def insert_sample(s):
 c=get_connection(); x=c.execute('INSERT INTO samples(timestamp,hostname,cpu_percent,memory_percent,load1,disk_used_percent) VALUES(?,?,?,?,?,?)',(s['timestamp'],s['hostname'],s['cpu_percent'],s['memory_percent'],s['load1'],s['disk_used_percent'])); i=x.lastrowid;c.commit();c.close();return i
def upsert_task(t,sid,ts):
 c=get_connection(); old=c.execute('SELECT task_id FROM tasks WHERE task_id=?',(t['task_id'],)).fetchone()
 if old: c.execute('UPDATE tasks SET last_seen=?,status=?,command=?,metadata=? WHERE task_id=?',(ts,t['status'],t['command'],t['metadata'],t['task_id']))
 else: c.execute('INSERT INTO tasks(task_id,category,name,command,first_seen,last_seen,status,metadata) VALUES(?,?,?,?,?,?,?,?)',(t['task_id'],t['category'],t['name'],t['command'],ts,ts,t['status'],t['metadata']))
 c.execute('INSERT INTO task_samples(task_id,sample_id,timestamp,pid,status,cpu_percent,memory_percent,rss_bytes) VALUES(?,?,?,?,?,?,?,?)',(t['task_id'],sid,ts,t['pid'],t['status'],t['cpu_percent'],t['memory_percent'],t['rss_bytes']));c.commit();c.close()
