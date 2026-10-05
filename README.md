# Linux Task Monitor

Supervision d'un serveur Linux : l'agent collecte l'état du système, des processus et des services systemd, détecte les problèmes dans l'historique (CPU, fuites mémoire, disque, services en échec…), recueille des diagnostics et propose des solutions, sans jamais rien exécuter lui-même. Tableau de bord web et résumé IA facultatif.

```
cd source/linux_task_monitor_v2
sudo ./install.sh
```

Puis ouvrez http://127.0.0.1:8000/ sur le serveur (ou via `ssh -L 8000:127.0.0.1:8000 serveur`).

Documentation complète : [source/linux_task_monitor_v2/README.md](source/linux_task_monitor_v2/README.md).
