# INC-001 — Investigation d'une activité PowerShell

## 1. Résumé

Une alerte a été générée à la suite de l'exécution de PowerShell avec une commande contenant `Invoke-WebRequest`.

L'objectif de l'investigation est de déterminer si l'activité correspond à une utilisation légitime de PowerShell ou à une activité potentiellement malveillante.

---

## 2. Source de données

- **Source :** Sysmon
- **Event ID :** 1 — Process Creation
- **SIEM :** Splunk Enterprise
- **Endpoint :** Windows 11
- **Utilisateur observé :** `USER\Administrator`

---

## 3. Commande observée

La commande suivante a été détectée :

```text
powershell.exe -NoProfile -Command Write-Output "Invoke-WebRequest"
```

---

## 4. Chronologie

| Heure | Activité | Observation |
|---|---|---|
| 13:27:47 | PowerShell lancé | Parent : `explorer.exe` |
| 13:30:18 | PowerShell exécuté | Présence de `Invoke-WebRequest` |
| 13:37:00 | PowerShell exécuté | Parent : `ekrn.exe` (ESET) |

---

## 5. Analyse

L'utilisation de PowerShell est une activité courante dans un environnement Windows.

La présence de `Invoke-WebRequest` mérite cependant une vérification, car cette commande peut être utilisée pour effectuer des requêtes HTTP ou récupérer des ressources depuis un serveur distant.

Dans ce cas, la commande observée utilise `Write-Output` et ne contient pas directement d'URL ni de téléchargement de fichier.

Le processus parent `explorer.exe` correspond à une utilisation interactive de PowerShell.

Une autre exécution a été observée avec `ekrn.exe`, processus associé à ESET Security.

---

## 6. Évaluation

**Verdict :** Activité probablement légitime.

**Sévérité :** Faible

### Justification

- Aucun téléchargement de fichier n'a été confirmé.
- Aucune URL malveillante n'a été observée.
- La commande observée utilise `Write-Output`.
- Le processus PowerShell est un binaire Windows légitime.
- L'exécution depuis `explorer.exe` est compatible avec une utilisation interactive.
- L'exécution depuis `ekrn.exe` peut être liée à ESET Security.

---

## 7. Actions de vérification

Les éléments suivants peuvent être vérifiés lors d'une investigation SOC :

1. Vérifier le processus parent et la chaîne de processus.
2. Examiner la ligne de commande complète.
3. Rechercher les connexions réseau associées au processus PowerShell.
4. Vérifier les événements Sysmon Event ID 3.
5. Rechercher d'autres exécutions PowerShell sur le même endpoint.
6. Vérifier la présence éventuelle d'URLs, de fichiers téléchargés ou d'indicateurs de compromission.

---

## 8. Conclusion

L'activité observée ne présente pas suffisamment d'éléments permettant de confirmer une activité malveillante.

L'alerte est donc classée comme **faible risque / probablement légitime**, tout en conservant une surveillance des éventuelles activités PowerShell associées.

**Statut :** Closed — Benign / Legitimate Activity
