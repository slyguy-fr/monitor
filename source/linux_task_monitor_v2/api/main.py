from fastapi import FastAPI,Query
from agent.database import init_db,get_connection
from agent.analyzer import analyze_latest,analyze_task
app=FastAPI(title='Linux Task Monitor',version='0.2.0');init_db()
@app.get('/')
def root():return {'application':'Linux Task Monitor','version':'0.2.0','status':'ok'}
@app.get('/health')
def health():return {'status':'healthy'}
@app.get('/system/latest')
def system_latest():
 c=get_connection();r=c.execute('SELECT * FROM samples ORDER BY id DESC LIMIT 1').fetchone();c.close();return dict(r) if r else {'message':'Aucune donnée'}
@app.get('/tasks')
def tasks(category:str|None=None,status:str|None=None,name:str|None=None,limit:int=Query(100,ge=1,le=1000)):
 c=get_connection();sql='SELECT * FROM tasks WHERE 1=1';p=[]
 if category:sql+=' AND category=?';p.append(category)
 if status:sql+=' AND status=?';p.append(status)
 if name:sql+=' AND name LIKE ?';p.append('%'+name+'%')
 sql+=' ORDER BY category,name LIMIT ?';p.append(limit);r=c.execute(sql,p).fetchall();c.close();return [dict(x) for x in r]
@app.get('/tasks/{task_id}')
def task(task_id:str):
 c=get_connection();r=c.execute('SELECT * FROM tasks WHERE task_id=?',(task_id,)).fetchone();c.close();return dict(r) if r else {'error':'Task not found'}
@app.get('/tasks/{task_id}/history')
def history(task_id:str,limit:int=Query(100,ge=1,le=1000)):
 c=get_connection();r=c.execute('SELECT * FROM task_samples WHERE task_id=? ORDER BY timestamp DESC LIMIT ?',(task_id,limit)).fetchall();c.close();return [dict(x) for x in r]
@app.get('/tasks/{task_id}/analysis')
def task_analysis(task_id:str):return analyze_task(task_id)
@app.get('/analysis')
def analysis():return {'alerts':analyze_latest()}
