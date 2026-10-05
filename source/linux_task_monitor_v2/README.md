# Linux Task Monitor V2

L'agent collecte toutes les 15 s l'état du système, des processus (regroupés par programme) et des services systemd dans une base SQLite. Toutes les minutes il analyse l'historique, détecte les problèmes (*findings*), recueille des diagnostics et propose des solutions. Il ne modifie jamais le système : les actions sont des propositions.

## Installation sur un serveur

```
sudo ./install.sh
curl http://127.0.0.1:8000/recommendations
```

Le script installe le code dans `/opt/linux-task-monitor`, crée l'utilisateur `ltm`, la base dans `/var/lib/linux-task-monitor`, la configuration dans `/etc/linux-task-monitor/monitor.env` et deux services :

- `linux-task-monitor` (agent) : tourne en root pour voir tous les processus, leurs descripteurs et le journal ; durci (`ProtectSystem=strict`, `NoNewPrivileges`, écriture limitée à sa base, priorité CPU/disque basse).
- `linux-task-monitor-api` : tourne en `ltm`, écoute sur `127.0.0.1:8000`. Pour l'exposer, définissez `LTM_API_HOST` et `LTM_API_TOKEN` dans `monitor.env` (en-tête `Authorization: Bearer <jeton>`).

Une ancienne base `/opt/linux-task-monitor/monitor.db` n'est pas déplacée automatiquement.

## Développement

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Agent : `python -m agent.main`
API : `python -m uvicorn api.main:app --host 127.0.0.1 --port 8000`

L'API expose les lignes de commande des processus (mots de passe et jetons masqués) : ne l'écoutez pas sur `0.0.0.0` sans `LTM_API_TOKEN`.

## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `LTM_DB_PATH` | `./monitor.db` | Chemin de la base SQLite (agent et API) |
| `LTM_INTERVAL_SECONDS` | `15` | Intervalle de collecte |
| `LTM_INCLUDE_KERNEL_THREADS` | `0` | Inclure les threads noyau |
| `LTM_TASK_SAMPLES_RETENTION_HOURS` | `48` | Rétention de l'historique par tâche |
| `LTM_SAMPLES_RETENTION_DAYS` | `30` | Rétention des mesures système |
| `LTM_RETENTION_CHECK_SECONDS` | `3600` | Fréquence du nettoyage |
| `LTM_ANALYSIS_INTERVAL_SECONDS` | `60` | Fréquence d'exécution des détecteurs |
| `LTM_API_TOKEN` | *(vide)* | Si défini, l'API exige `Authorization: Bearer <jeton>` (sauf `/` et `/health`) |
| `LTM_THRESHOLD_<NOM>` | voir `agent/config.py` | Seuil d'un détecteur, ex. `LTM_THRESHOLD_TASK_CPU_PERCENT=90` |

## Détection des problèmes

Toutes les `LTM_ANALYSIS_INTERVAL_SECONDS`, l'agent analyse l'historique (pas seulement la dernière mesure) et ouvre des *findings* dans la table `findings`. Un finding reste ouvert tant que le problème est détecté (seuil de fermeture plus bas que le seuil d'ouverture) et passe à `resolved` après `LTM_THRESHOLD_RESOLVE_AFTER_RUNS` analyses (2 par défaut) sans détection. Une tâche concernée prend la sévérité de son pire finding ouvert dans `tasks.status`.

| Détecteur | Déclenchement par défaut |
|---|---|
| `sustained_task_cpu` | tâche ≥ 80 % CPU en moyenne sur 5 min (80 % des mesures au-dessus) ; critique si ≥ 75 % de la machine |
| `cpu_saturation` | CPU machine ≥ 90 % sur 5 min, charge 5 min ≥ 1,5 × cœurs ou PSI CPU ≥ 20 % |
| `memory_leak` | RSS en hausse régulière sur ≥ 1 h (R² ≥ 0,8, +20 % et +50 Mo), à nombre de processus constant ; critique si mémoire épuisée en < 24 h |
| `memory_pressure` | mémoire ≥ 90 % sur 5 min, swap ≥ 50 % et en hausse ou PSI mémoire ≥ 10 % |
| `oom_kill` | le noyau a tué un processus (OOM) dans les 15 dernières minutes |
| `zombies` | zombies non récupérés par le même parent depuis ≥ 2 min (ou ≥ 10 zombies) |
| `io_wait` | processus en état D sur 3 mesures consécutives, iowait ≥ 20 % sur 5 min ou PSI I/O ≥ 20 % |
| `disk_space` | point de montage ≥ 85 % ou inodes ≥ 90 % ; critique si ≥ 95 % ou plein dans < 24 h au rythme actuel |
| `service_failed` | service systemd en état `failed` |
| `restart_loop` | ≥ 3 redémarrages d'un service en 15 min |
| `fd_exhaustion` | processus à ≥ 80 % de sa limite de descripteurs de fichiers |
| `process_explosion` | nombre de processus d'une tâche × 5 en 10 min (et ≥ 50) |

## Modèle de données

- **Processus** : un programme = une tâche. Les processus d'un même exécutable dans la même unité systemd sont regroupés (CPU, mémoire, threads et descripteurs additionnés, `process_count`). Pour les interpréteurs (python, node, java…), le script ou module fait partie de l'identité. L'unité systemd du processus est dans `unit`.
- **Services systemd** : CPU et mémoire viennent de la comptabilité systemd (`CPUUsageNSec`, `MemoryCurrent`). Le nombre de redémarrages et le résultat sont dans `metadata`.
- `tasks.status` : `ok`, `warning`, `critical` ou `gone`. `tasks.state` : `active` ou `gone`. L'état brut (`sleeping`, `failed/failed`…) est dans `task_samples.raw_status`.
- Les services inactifs ne reçoivent une ligne d'historique que lorsque leur état ou leur nombre de redémarrages change ; les services en cours d'exécution sont mesurés à chaque cycle.
- `disk_samples` : utilisation de chaque point de montage local (octets et inodes) à chaque cycle.
- La base existante est migrée automatiquement au démarrage.

## Tableau de bord

Ouvrez `http://127.0.0.1:8000/` dans un navigateur (redirige vers `/ui/`) :

- état actuel (CPU, mémoire, swap, charge, iowait, pression mémoire) et graphiques sur 1 à 48 h ;
- problèmes ouverts avec causes probables, actions proposées (bouton « Copier ») et diagnostics, bouton « Ignorer 24 h » ;
- disques, plus gros consommateurs CPU/mémoire, recherche de tâche et historique d'une tâche.

La page n'utilise aucune ressource externe. Si `LTM_API_TOKEN` est défini, elle demande le jeton (conservé dans le navigateur). Depuis un autre poste : `ssh -L 8000:127.0.0.1:8000 serveur` puis `http://127.0.0.1:8000/`.

## Endpoints

`/system/latest`, `/system/history?hours=6&points=240`, `/disks/latest`, `/tasks/top?by=cpu|memory`, `/tasks`, `/tasks/{task_id}`, `/tasks/{task_id}/history`, `/tasks/{task_id}/analysis`, `/recommendations`, `/analysis`, `/findings`, `/findings/{id}`, `POST /findings/{id}/ack`

- `/recommendations?severity=critical&include_acked=false` : findings ouverts, les plus graves en premier, chacun avec sa recommandation (`/analysis` en est un alias) :
  ```json
  {"summary": "Service en échec : nginx.service (exit-code)",
   "probable_causes": ["Le programme s'est arrêté en erreur (code 1) : configuration invalide, …"],
   "actions": [{"title": "Lire l'erreur dans le journal", "command": "journalctl -u nginx.service -n 100 --no-pager", "risk": "safe"},
               {"title": "Tester la configuration", "command": "nginx -t", "risk": "safe"},
               {"title": "Après correction, redémarrer le service", "command": "systemctl restart nginx.service", "risk": "low"}],
   "diagnostics": [{"title": "Derniers journaux du service", "command": "journalctl -u nginx.service -n 30 …", "output": "…"}]}
  ```
  `risk` : `safe` (lecture seule), `low` (modification réversible), `disruptive` (interrompt un service).
- Les diagnostics (journal du service, `du`, `ps`, fichiers supprimés encore ouverts, messages OOM…) sont recueillis une seule fois, à l'ouverture du finding, en lecture seule, avec délai maximal et priorité basse.
- `POST /findings/{id}/ack?hours=24` : masque un finding de `/recommendations` pendant N heures (`hours=0` annule).
- `/findings?status=open|resolved&severity=warning|critical&detector=memory_leak&task_id=...` (par défaut : ouverts).
- `/tasks/{task_id}` inclut `open_findings` ; `/tasks/{task_id}/analysis` inclut les findings avec leur recommandation.

Filtres : `/tasks?category=process|systemd`, `/tasks?status=ok|warning|critical|gone`, `/tasks?state=active|gone`, `/tasks?name=postgres`

Une tâche inconnue renvoie une erreur 404.

## Tests

```
pip install -r requirements-dev.txt
pytest
ruff check . && ruff format --check .
```
