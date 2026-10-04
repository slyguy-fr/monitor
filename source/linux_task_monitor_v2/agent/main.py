import time
from .collector import collect_all
from .database import init_db,insert_sample,upsert_task
from .analyzer import analyze_latest
INTERVAL=10
def main():
 init_db();print('Linux Task Monitor V2 démarré.')
 while True:
  try:
   s,tasks=collect_all();sid=insert_sample(s)
   for t in tasks:upsert_task(t,sid,s['timestamp'])
   for a in analyze_latest():print(f"[{a['severity'].upper()}] {a['message']}")
   print(f"{s['timestamp']} | CPU {s['cpu_percent']:.1f}% | RAM {s['memory_percent']:.1f}% | Tâches {len(tasks)}");time.sleep(INTERVAL)
  except KeyboardInterrupt: print('\nArrêt.');break
  except Exception as e: print(f'Erreur: {e}');time.sleep(INTERVAL)
if __name__=='__main__':main()
