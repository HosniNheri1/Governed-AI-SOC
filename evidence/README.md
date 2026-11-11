# evidence/ — Preuves du Day 6 (scénario R-03)

Ce dossier contient les preuves du Day 6 du projet Governed AI-Assisted SOC : détection d'un brute force SSH, scoring par le modèle ML, puis décision humaine dans un workflow SOAR.

Chaîne couverte : Suricata → Splunk (alerte) → webhook → Shuffle → service FastAPI (score) → `analyst-approval` → blocage simulé.

## Contenu

| Fichier | Étape de la chaîne | Ce qu'il montre |
|---|---|---|
| `R-03_splunk_alert_to_shuffle.png` | Alerte Splunk → Shuffle | Alerte Splunk déclenchée et transmise au workflow Shuffle |
| `R-03_splunk_webhook_log.png` | Webhook Splunk → Shuffle | Journal d'envoi (`component=sendmodalert action=webhook`) : exécution de 13:30 UTC, réponse HTTP 200 |
| `R-03_fastapi_score_masque.png` | Service ML | Sortie du nœud `ml-score-session` : HTTP 200, label `ssh_bruteforce`, score 0.985, seuil 0.7, `alert: true` |
| `R-03_approval_continue.png` | Décision humaine + blocage simulé | Sortie du nœud `simulated-block` : `decision: approve`, analyste masqué, `alert_ts` 2026-11-11T13:30:00Z, `source: splunk_alert` |
| `R-03_decline_aborted.png` | Décision humaine (refus) | Exécution ABORTED sur le nœud `analyst-approval` (voir réserve) |

## Périmètre

- Le workflow ne couvre que **SSH** pour l'instant. FTP et HTTP sont exclus volontairement, à cause du risque lié à `src_ip` (blocage possible de la victime par erreur). Cette décision est consignée dans le registre de risques (ligne R-03).
- Alerte Splunk : throttle de 10 minutes sur `src_ip`, planification cron `*/5 * * * *`, fenêtre de recherche « Last 5 minutes ».
- Le blocage final est **simulé** : aucune règle réelle n'est appliquée.

## Notes importantes

### Score du modèle
La capture `R-03_fastapi_score_masque.png` montre le score de la session de test `sess_20261107_104736_27248` (07/11/2026), traitée par l'exécution de 13:30 UTC (11/11/2026). Il s'agit d'une session de test enregistrée, pas d'une attaque générée pendant cette exécution. Le modèle classe cette session en `ssh_bruteforce` avec 0.985, très au-dessus du seuil de 0.7. L'URL du service est masquée.

### Décisions humaines

| Date | Exécution | Décision |
|---|---|---|
| 09/11/2026 | run `curl` de test | ABORTED après 5 min 10 s, sans validation |
| 11/11/2026, 13:30 UTC | exécution déclenchée par l'alerte Splunk | `approve` (analyste masqué), voir `R-03_approval_continue.png` |

### Réserve sur `R-03_decline_aborted.png`
La capture provient d'un run `curl` du 09/11/2026, terminé en **ABORTED après 5 min 10 s**. Le motif du refus n'a pas été conservé dans les journaux Shuffle. Elle atteste que l'exécution a été interrompue sans validation, mais pas du motif saisi par l'analyste.

### Limites connues
- L'enrichissement AbuseIPDB / VirusTotal n'est pas couvert par ces preuves.
- L'export du workflow Shuffle n'est pas inclus dans ce dossier.

### Fuseaux horaires
- La VM Kali est en **UTC-5**, les journaux Splunk en **UTC**.
- Les horodatages doivent être convertis avant d'être comparés entre captures (ex. : exécution Splunk de 13:30 UTC).

### Données masquées
Les URL (webhook Shuffle, service ML), jetons et autres données sensibles sont masqués dans les captures.
