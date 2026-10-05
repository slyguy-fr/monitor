"""Turn a finding (evidence + diagnostics) into probable causes and proposed actions.

Nothing here is executed: actions are proposals with a risk level
("safe" = read-only, "low" = reversible change, "disruptive" = interrupts the service).
"""

import math

SAFE, LOW, DISRUPTIVE = "safe", "low", "disruptive"
CONFIG_TESTS = {
    "nginx": "nginx -t",
    "apache2": "apache2ctl configtest",
    "httpd": "apachectl configtest",
    "ssh": "sshd -t",
    "sshd": "sshd -t",
    "haproxy": "haproxy -c -f /etc/haproxy/haproxy.cfg",
    "postfix": "postfix check",
    "named": "named-checkconf",
    "bind9": "named-checkconf",
    "php-fpm": "php-fpm -t",
}
FAILURE_CAUSES = {
    "exit-code": "Le programme s'est arrêté en erreur{code} : configuration invalide, "
    "fichier ou dépendance manquante, port déjà utilisé…",
    "signal": "Le programme a planté (tué par un signal)",
    "core-dump": "Le programme a planté (core dump)",
    "timeout": "Démarrage ou arrêt trop long (TimeoutStartSec / TimeoutStopSec)",
    "oom-kill": "Tué par le noyau par manque de mémoire",
    "start-limit-hit": "Trop de redémarrages rapprochés : systemd a abandonné (StartLimitBurst)",
    "resources": "Ressource manquante au démarrage (fichier, répertoire, utilisateur, port)",
    "exec-condition": "Condition d'exécution non remplie",
}
TEMPLATES = {}


def template(name):
    def register(func):
        TEMPLATES[name] = func
        return func

    return register


def action(title, command=None, risk=SAFE):
    return {"title": title, "command": command, "risk": risk}


class Subject:
    def __init__(self, finding):
        ev = finding.get("evidence") or {}
        unit = ev.get("unit") or finding.get("task_unit")
        self.unit = unit if unit and unit.endswith(".service") else None
        self.name = finding.get("task_name") or unit or finding["subject"]
        self.pid = finding.get("pid") or ev.get("parent_pid")
        self.pid_ref = str(self.pid) if self.pid else "<PID>"

    @property
    def service_base(self):
        return (self.unit or self.name).removesuffix(".service").split("@")[0]

    def restart(self, title="Redémarrer pour retrouver un état sain", risk=DISRUPTIVE):
        if self.unit:
            return action(title, f"systemctl restart {self.unit}", risk)
        return action(f"{title} (arrêt puis relance du programme)", f"kill {self.pid_ref}", risk)


def memory_limit(mb, factor=1.5):
    target = max(mb, 1) * factor
    if target >= 1024:
        return f"{math.ceil(target / 1024)}G"
    return f"{math.ceil(target / 256) * 256}M"


def _names(tasks, limit=3):
    return ", ".join(t["name"] for t in (tasks or [])[:limit])


def _diagnostic(finding, title):
    for d in (finding.get("context") or {}).get("diagnostics", []):
        if d.get("title") == title:
            return d
    return None


@template("sustained_task_cpu")
def _task_cpu(f, s, ev):
    actions = [
        action("Voir quels threads consomment le CPU", f"top -H -p {s.pid_ref}"),
        action(
            "Voir dans quelles fonctions le programme passe son temps", f"perf top -p {s.pid_ref}"
        ),
    ]
    if s.unit:
        actions += [
            action(
                f"Plafonner {s.unit} à un cœur (persistant, réversible)",
                f"systemctl set-property {s.unit} CPUQuota=100%",
                LOW,
            ),
            s.restart("Redémarrer le service si le CPU reste bloqué (boucle)"),
        ]
    else:
        actions += [
            action("Baisser sa priorité CPU", f"renice -n 10 -p {s.pid_ref}", LOW),
            s.restart("Arrêter le processus s'il est bloqué dans une boucle"),
        ]
    if (ev.get("machine_share_percent") or 0) >= 50:
        actions.append(action("Ajouter des cœurs ou répartir la charge sur d'autres serveurs"))
    return {
        "probable_causes": [
            "Charge réelle élevée (traitement lourd, pic d'activité)",
            "Boucle active ou bug applicatif",
            "Tâche planifiée ou traitement batch lancé au mauvais moment",
        ],
        "actions": actions,
    }


@template("cpu_saturation")
def _cpu_saturation(f, s, ev):
    top = ev.get("top_tasks") or []
    causes = []
    if top:
        causes.append(f"Processus les plus consommateurs : {_names(top)}")
    causes += [
        "Serveur sous-dimensionné pour la charge actuelle",
        "Trop de tâches simultanées (charge supérieure au nombre de cœurs)",
    ]
    actions = [action("Identifier les processus en cause", "top -o %CPU")]
    if top:
        first = Subject(
            {"subject": top[0]["task_id"], "task_name": top[0]["name"], "task_unit": top[0]["unit"]}
        )
        if first.unit:
            actions.append(
                action(
                    f"Plafonner le plus gros consommateur ({first.unit})",
                    f"systemctl set-property {first.unit} CPUQuota=100%",
                    LOW,
                )
            )
        else:
            actions.append(
                action(
                    f"Baisser la priorité de {first.name}",
                    f"renice -n 10 -p $(pgrep -o -x {first.name})",
                    LOW,
                )
            )
    actions.append(action("Ajouter des cœurs ou répartir la charge sur d'autres serveurs"))
    return {"probable_causes": causes, "actions": actions}


@template("memory_leak")
def _memory_leak(f, s, ev):
    limit = memory_limit(ev.get("rss_mb") or 0)
    actions = [
        action("Voir les zones mémoire qui grossissent", f"pmap -x {s.pid_ref} | tail -n 20")
    ]
    if s.unit:
        actions += [
            action(
                f"Plafonner la mémoire de {s.unit} pour protéger le serveur",
                f"systemctl set-property {s.unit} MemoryMax={limit}",
                LOW,
            ),
            action(
                "En attendant un correctif, redémarrer automatiquement chaque jour",
                f"systemctl edit {s.unit}  # [Service] RuntimeMaxSec=1d",
                LOW,
            ),
            s.restart("Redémarrer maintenant pour libérer la mémoire"),
        ]
    else:
        actions.append(s.restart("Redémarrer le programme pour libérer la mémoire"))
    actions.append(action("Mettre à jour l'application ou signaler la fuite à l'éditeur"))
    causes = [
        "Fuite mémoire dans l'application",
        "Cache interne sans limite de taille",
        "Croissance normale liée à une montée en charge (à confirmer)",
    ]
    return {"probable_causes": causes, "actions": actions}


@template("memory_pressure")
def _memory_pressure(f, s, ev):
    top = ev.get("top_tasks") or []
    actions = [
        action("Identifier les plus gros consommateurs", "ps -eo pid,rss,args --sort=-rss | head"),
    ]
    if top and top[0].get("unit"):
        unit = top[0]["unit"]
        rss_mb = (top[0].get("rss_bytes") or 0) / 1048576
        actions.append(
            action(
                f"Plafonner la mémoire de {unit}",
                f"systemctl set-property {unit} MemoryMax={memory_limit(rss_mb, 1.2)}",
                LOW,
            )
        )
    if (ev.get("swap_percent") or 0) > 0:
        actions.append(action("Réduire l'utilisation du swap", "sysctl -w vm.swappiness=10", LOW))
    actions.append(action("Ajouter de la RAM, ou du swap en dépannage"))
    causes = ["Un ou plusieurs processus consomment trop de mémoire"]
    if top:
        causes[0] += f" : {_names(top)}"
    causes.append("Serveur sous-dimensionné pour les services hébergés")
    return {"probable_causes": causes, "actions": actions}


@template("oom_kill")
def _oom(f, s, ev):
    top = ev.get("top_tasks") or []
    return {
        "probable_causes": [
            "La mémoire disponible a été épuisée et le noyau a tué un processus",
            "Un service a atteint sa limite MemoryMax",
            *([f"Plus gros consommateurs : {_names(top)}"] if top else []),
        ],
        "actions": [
            action(
                "Voir quel processus a été tué et pourquoi",
                "journalctl -k | grep -iE 'out of memory|killed process'",
            ),
            action(
                "Plafonner la mémoire du service en cause",
                "systemctl set-property <unité> MemoryMax=…",
                LOW,
            ),
            action(
                "Protéger les services critiques du tueur OOM",
                "systemctl edit <service-critique>  # [Service] OOMScoreAdjust=-500",
                LOW,
            ),
            action("Ajouter de la RAM ou du swap"),
        ],
    }


@template("disk_space")
def _disk(f, s, ev):
    mount = f["subject"]
    actions = [
        action(
            "Trouver ce qui occupe l'espace", f"du -xh --max-depth=2 {mount} | sort -rh | head -20"
        )
    ]
    causes = []
    if mount in ("/", "/var", "/var/log"):
        causes.append("Journaux qui grossissent (journald, /var/log)")
        actions += [
            action("Réduire le journal systemd", "journalctl --vacuum-size=500M", LOW),
            action("Forcer la rotation des logs", "logrotate -f /etc/logrotate.conf", LOW),
        ]
    if mount in ("/", "/var"):
        causes.append("Caches de paquets")
        actions.append(
            action("Vider le cache des paquets", "apt-get clean  # ou: dnf clean all", LOW)
        )
    docker = _diagnostic(f, "Espace utilisé par Docker")
    if docker and docker.get("reclaimable"):
        causes.append("Images, conteneurs et volumes Docker inutilisés")
        actions.append(
            action("Supprimer les ressources Docker inutilisées", "docker system prune", DISRUPTIVE)
        )
    deleted = _diagnostic(f, "Fichiers supprimés encore ouverts")
    if deleted and deleted.get("significant_bytes"):
        causes.append(
            f"Fichiers supprimés mais encore ouverts par un processus : "
            f"{deleted['significant_bytes'] // 1048576} Mo non libérés"
        )
        actions.append(
            action(
                "Redémarrer les processus qui gardent ces fichiers ouverts (voir diagnostics)",
                None,
                DISRUPTIVE,
            )
        )
    if (ev.get("inodes_percent") or 0) >= 90:
        causes.append("Très grand nombre de petits fichiers (inodes épuisés)")
        actions.append(
            action(
                "Trouver les répertoires avec le plus de fichiers",
                f"find {mount} -xdev -type f | cut -d/ -f1-4 | sort | uniq -c | sort -rn | head",
            )
        )
    if ev.get("hours_to_full") is not None:
        causes.append(f"Remplissage rapide : plein dans environ {ev['hours_to_full']:.0f} h")
    causes.append("Sauvegardes, dumps ou fichiers temporaires oubliés")
    actions.append(action("Agrandir le volume si les données sont légitimes"))
    return {"probable_causes": causes, "actions": actions}


@template("zombies")
def _zombies(f, s, ev):
    return {
        "probable_causes": [
            f"{s.name} ne récupère pas ses processus enfants terminés (wait() manquant)",
            "Le processus parent est bloqué ou surchargé",
        ],
        "actions": [
            action("Lister les zombies", f"ps -o pid,stat,etime,args --ppid {s.pid_ref}"),
            action(
                "Demander au parent de récupérer ses enfants", f"kill -s SIGCHLD {s.pid_ref}", LOW
            ),
            s.restart("Redémarrer le parent (les zombies disparaissent avec lui)"),
            action("Corriger le programme parent (appeler waitpid ou ignorer SIGCHLD)"),
        ],
    }


@template("io_wait")
def _io_wait(f, s, ev):
    actions = [action("Voir quels processus lisent ou écrivent le plus", "iotop -oPa")]
    if f["subject_type"] == "task":
        actions.append(
            action("Voir où le processus est bloqué dans le noyau", f"cat /proc/{s.pid_ref}/stack")
        )
        if s.unit:
            actions.append(
                action(
                    f"Réduire la priorité disque de {s.unit}",
                    f"systemctl set-property {s.unit} IOWeight=10",
                    LOW,
                )
            )
        else:
            actions.append(action("Réduire sa priorité disque", f"ionice -c3 -p {s.pid_ref}", LOW))
    actions += [
        action("Chercher des erreurs disque", "dmesg -T | grep -iE 'error|timeout|reset'"),
        action("Vérifier la santé du disque", "smartctl -a /dev/sdX"),
        action("Vérifier les montages réseau", "findmnt -t nfs,nfs4,cifs"),
    ]
    return {
        "probable_causes": [
            "Disque saturé par un processus (sauvegarde, base de données, swap)",
            "Disque lent ou défaillant",
            "Montage réseau (NFS/CIFS) qui ne répond plus",
        ],
        "actions": actions,
    }


def _service_failure_causes(ev):
    result = ev.get("result")
    code = ev.get("exec_main_status")
    text = FAILURE_CAUSES.get(result, "Cause inconnue : voir le journal du service")
    return [text.format(code=f" (code {code})" if code else "")]


def _config_test(s):
    test = CONFIG_TESTS.get(s.service_base)
    return [action("Tester la configuration", test)] if test else []


@template("service_failed")
def _service_failed(f, s, ev):
    unit = s.unit or s.name
    return {
        "probable_causes": _service_failure_causes(ev),
        "actions": [
            action("Lire l'erreur dans le journal", f"journalctl -u {unit} -n 100 --no-pager"),
            action("Voir la configuration du service", f"systemctl cat {unit}"),
            *_config_test(s),
            action("Après correction, redémarrer le service", f"systemctl restart {unit}", LOW),
            action("Effacer l'état d'échec", f"systemctl reset-failed {unit}", LOW),
            action(
                "Si le service est inutile, le désactiver", f"systemctl disable --now {unit}", LOW
            ),
        ],
    }


@template("restart_loop")
def _restart_loop(f, s, ev):
    unit = s.unit or s.name
    return {
        "probable_causes": [
            "Le service plante juste après son démarrage et systemd le relance (Restart=)",
            *_service_failure_causes(ev),
        ],
        "actions": [
            action("Lire l'erreur dans le journal", f"journalctl -u {unit} -n 100 --no-pager"),
            *_config_test(s),
            action(
                "Espacer les redémarrages pour limiter l'impact",
                f"systemctl edit {unit}  # [Service] RestartSec=30s",
                LOW,
            ),
            action("Arrêter le service le temps de corriger", f"systemctl stop {unit}", DISRUPTIVE),
        ],
    }


@template("fd_exhaustion")
def _fd(f, s, ev):
    actions = [
        action(
            "Voir quels fichiers ou connexions sont ouverts",
            f"ls -l /proc/{s.pid_ref}/fd | awk '{{print $NF}}' | sort | uniq -c | sort -rn | head",
        )
    ]
    if s.unit:
        actions.append(
            action(
                "Augmenter la limite du service (puis redémarrer)",
                f"systemctl edit {s.unit}  # [Service] LimitNOFILE=65536",
                LOW,
            )
        )
    else:
        actions.append(
            action(
                "Augmenter la limite du processus",
                f"prlimit --pid {s.pid_ref} --nofile=65536:65536",
                LOW,
            )
        )
    return {
        "probable_causes": [
            "Fuite de descripteurs (fichiers ou connexions jamais fermés)",
            "Limite trop basse pour la charge (beaucoup de connexions simultanées)",
        ],
        "actions": actions,
    }


@template("process_explosion")
def _explosion(f, s, ev):
    actions = [
        action("Voir les processus créés", f"ps --ppid {s.pid_ref} -o pid,etime,args | head -20"),
        action("Voir l'arbre des processus", f"pstree -p {s.pid_ref}"),
    ]
    if s.unit:
        actions.append(
            action(
                f"Limiter le nombre de processus de {s.unit}",
                f"systemctl set-property {s.unit} TasksMax=500",
                LOW,
            )
        )
    else:
        actions.append(action("Arrêter les processus en trop", f"pkill -P {s.pid_ref}", DISRUPTIVE))
    return {
        "probable_causes": [
            "Pool de workers sans limite ou mal configuré",
            "Boucle de création de processus ou tâches planifiées qui se chevauchent",
            "Pic de trafic légitime",
        ],
        "actions": actions,
    }


def _generic(f, s, ev):
    return {"probable_causes": [], "actions": []}


def recommend(finding):
    subject = Subject(finding)
    rec = TEMPLATES.get(finding["detector"], _generic)(
        finding, subject, finding.get("evidence") or {}
    )
    return {
        "summary": finding["title"],
        "severity": finding["severity"],
        **rec,
        "diagnostics": (finding.get("context") or {}).get("diagnostics", []),
    }
