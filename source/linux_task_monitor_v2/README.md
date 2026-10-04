# Linux Task Monitor V2

V2 ajoute le registre des tâches persistantes, les catégories process/systemd, l'historique et les filtres API.

Installation:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Agent: python -m agent.main
API: python -m uvicorn api.main:app --host 0.0.0.0 --port 8000

Endpoints: /tasks, /tasks/{task_id}, /tasks/{task_id}/history, /tasks/{task_id}/analysis, /analysis
Filtres: /tasks?category=process, /tasks?category=systemd, /tasks?status=warning, /tasks?name=postgres
