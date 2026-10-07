# INC-005 — Investigation EDR d'une activité PowerShell

## 1. Résumé

Une détection EDR-style a identifié une exécution PowerShell contenant l'indicateur `Invoke-WebRequest`.

L'objectif de l'investigation est de déterminer si cette activité correspond à un comportement malveillant ou à une activité légitime de laboratoire.

---

## 2. Source de données

- **Endpoint telemetry :** Sysmon
- **Event ID :** 1 — Process Creation
- **Event ID :** 3 — Network Connection
- **SIEM :** Splunk Enterprise
- **Type d'analyse :** EDR Process Investigation

---

## 3. Détection

La règle a détecté :

- **Processus :** PowerShell
- **Parent :** PowerShell
- **Indicateur :** `Invoke-WebRequest`
- **Sévérité initiale :** Medium

---

## 4. Process Tree

L'analyse des `ProcessId` et `ParentProcessId` a permis de reconstruire la chaîne :

`explorer.exe → powershell.exe → powershell.exe`

Le deuxième processus PowerShell contenait :

`Write-Output "Invoke-WebRequest"`

---

## 5. Analyse du comportement

`Invoke-WebRequest` peut être utilisé par PowerShell pour effectuer des requêtes HTTP et peut donc constituer un indicateur intéressant dans une détection SOC.

Cependant, la présence de ce mot-clé ne suffit pas à confirmer une activité malveillante.

Dans ce cas, la commande observée utilisait `Write-Output` pour afficher le texte `Invoke-WebRequest`.

Aucun téléchargement n'a été confirmé.

---

## 6. Analyse réseau

Une recherche Sysmon Event ID 3 a été réalisée afin de rechercher une connexion réseau associée au processus analysé.

**Résultat :** aucun événement réseau correspondant au `ProcessId` analysé n'a été trouvé dans les données recherchées.

Cela indique qu'aucune connexion réseau Sysmon n'a été observée pour ce processus dans le périmètre analysé.

---

## 7. Triage SOC

| Élément | Résultat |
|---|---|
| PowerShell | Détecté |
| `Invoke-WebRequest` | Détecté |
| Process Tree | Identifiée |
| Commande de téléchargement confirmée | Non |
| Connexion réseau Sysmon associée | Non observée |
| Compromission confirmée | Non |

---

## 8. Verdict

**Classification :** Benign / Test Activity

**Severity :** Medium — Detection

**Final Risk:** Low

**Status:** Closed — Benign / Test Activity

### Justification

La détection fonctionne correctement et identifie un indicateur PowerShell potentiellement intéressant.

Cependant, l'activité analysée correspond à un test de laboratoire et aucun téléchargement ou indicateur de compromission n'a été confirmé.

---

## 9. MITRE ATT&CK Context

PowerShell peut être utilisé par des attaquants pour exécuter des commandes et scripts.

Cette activité peut être associée à :

**T1059.001 — Command and Scripting Interpreter: PowerShell**

La technique MITRE ne signifie pas que l'activité observée est malveillante ; elle fournit uniquement un contexte pour la détection.

---

## 10. Conclusion

L'EDR-style detection a correctement identifié une activité PowerShell contenant un indicateur potentiellement suspect.

L'investigation a permis de :

- identifier le processus ;
- reconstruire le Process Tree ;
- analyser la CommandLine ;
- rechercher une activité réseau ;
- évaluer le contexte ;
- classifier l'événement.

**Final Verdict: Benign / Test Activity**

Cette investigation démontre qu'une détection EDR doit toujours être suivie d'une analyse contextuelle avant de confirmer une compromission.

---

## 11. SOC Response Workflow

### Triage

- Vérifier le processus PowerShell et son processus parent.
- Examiner la CommandLine complète.
- Vérifier l'indicateur ayant déclenché la détection.
- Rechercher une connexion réseau associée au processus.

### Investigation

- Analyser le Process Tree.
- Vérifier les événements Sysmon Event ID 1 et 3.
- Rechercher une URL, un téléchargement ou une commande PowerShell suspecte.
- Vérifier les éventuels IOC.
- Déterminer si l'activité correspond à un test, une activité légitime ou un comportement malveillant.

### Response Decision

L'analyse a confirmé une activité de laboratoire sans compromission.

- **Containment :** Non requis
- **Escalation :** Non requise
- **Action :** Documenter le résultat et fermer l'alerte

### Closure

**Classification :** Benign / Test Activity

**Final Severity :** Low

**Status :** Closed — Benign / Test Activity
