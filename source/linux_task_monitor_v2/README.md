# Linux Task Monitor V2

L'agent collecte toutes les 15 s l'état du système, des processus (regroupés par programme) et des services systemd dans une base SQLite. L'API expose ces données et leur historique.

## Installation

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Agent : `python -m agent.main`
API : `python -m uvicorn api.main:app --host 127.0.0.1 --port 8000`

L'API expose les lignes de commande des processus : ne l'écoutez pas sur `0.0.0.0` sans protection.

## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `LTM_DB_PATH` | `./monitor.db` | Chemin de la base SQLite (agent et API) |
| `LTM_INTERVAL_SECONDS` | `15` | Intervalle de collecte |
| `LTM_INCLUDE_KERNEL_THREADS` | `0` | Inclure les threads noyau |
| `LTM_TASK_SAMPLES_RETENTION_HOURS` | `48` | Rétention de l'historique par tâche |
| `LTM_SAMPLES_RETENTION_DAYS` | `30` | Rétention des mesures système |
| `LTM_RETENTION_CHECK_SECONDS` | `3600` | Fréquence du nettoyage |

## Modèle de données

- **Processus** : un programme = une tâche. Les processus d'un même exécutable dans la même unité systemd sont regroupés (CPU, mémoire, threads et descripteurs additionnés, `process_count`). Pour les interpréteurs (python, node, java…), le script ou module fait partie de l'identité. L'unité systemd du processus est dans `unit`.
- **Services systemd** : CPU et mémoire viennent de la comptabilité systemd (`CPUUsageNSec`, `MemoryCurrent`). Le nombre de redémarrages et le résultat sont dans `metadata`.
- `tasks.status` : `ok`, `warning`, `critical` ou `gone`. `tasks.state` : `active` ou `gone`. L'état brut (`sleeping`, `failed/failed`…) est dans `task_samples.raw_status`.
- La base existante est migrée automatiquement au démarrage.

## Endpoints

`/system/latest`, `/tasks`, `/tasks/{task_id}`, `/tasks/{task_id}/history`, `/tasks/{task_id}/analysis`, `/analysis`

Filtres : `/tasks?category=process|systemd`, `/tasks?status=ok|warning|critical|gone`, `/tasks?state=active|gone`, `/tasks?name=postgres`

Une tâche inconnue renvoie une erreur 404.

## Tests

```
pip install -r requirements-dev.txt
pytest
ruff check . && ruff format --check .
```
