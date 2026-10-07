# Windows + Splunk — SOC Detection & Investigation Lab

## Présentation

Projet personnel de laboratoire SOC basé sur **Windows 11, Sysmon et Splunk Enterprise**.

L'objectif est de reproduire un workflow SOC réaliste :

**Endpoint Telemetry → SIEM → Detection → Triage → Investigation → MITRE ATT&CK → Verdict**

Le laboratoire couvre la détection et l'investigation d'activités Windows potentiellement suspectes, avec une approche orientée **SOC Analyst / EDR**.

---

## Architecture

Windows 11
→ Sysmon
→ Endpoint Telemetry
→ Splunk Enterprise
→ Detection Rules
→ SOC Investigation
→ MITRE ATT&CK
→ Final Verdict

### Télémétrie utilisée

- Sysmon Event ID 1 — Process Creation
- Sysmon Event ID 3 — Network Connection
- Windows Security Event ID 4624 — Successful Logon
- Windows Security Event ID 4625 — Failed Logon

---

## Détections développées

| Détection | Source | Objectif |
|---|---|---|
| PowerShell Detection | Sysmon EID 1 | Identifier des commandes PowerShell potentiellement suspectes |
| Failed Logon Detection | Windows Security 4625 | Détecter plusieurs échecs d'authentification |
| LOLBin Detection | Sysmon EID 1 | Identifier l'utilisation de binaires Windows pouvant être détournés |
| EDR PowerShell Detection | Sysmon EID 1 | Détecter des comportements PowerShell suspects |
| Parent-Child Process Detection | Sysmon EID 1 | Analyser les relations entre processus |
| Network Connection Analysis | Sysmon EID 3 | Investiguer les connexions réseau endpoint |

---

## Investigations SOC

Chaque détection est accompagnée d'une investigation documentée.

- [INC-001 — PowerShell Investigation](investigations/INC-001-powershell.md)
- [INC-002 — Network Connection Investigation](investigations/INC-002-network-connection.md)
- [INC-003 — Windows Authentication Investigation](investigations/INC-003-windows-authentication.md)
- [INC-004 — LOLBin Investigation](investigations/INC-004-lolbin.md)
- [INC-005 — EDR PowerShell Investigation](investigations/INC-005-edr-powershell.md)
- [INC-006 — Parent-Child Process Investigation](investigations/INC-006-parent-child-process.md)

---

## Detection Engineering

Les règles Splunk sont disponibles dans le dossier `detections/`.

- [PowerShell Detection](detections/powershell_detection.spl)
- [Failed Logon Detection](detections/failed_logon_detection.spl)
- [LOLBin Detection](detections/lolbin_detection.spl)
- [EDR PowerShell Detection](detections/edr_powershell_detection.spl)
- [Parent-Child Process Detection](detections/parent_child_process_detection.spl)

Les détections utilisent notamment :

- CommandLine analysis
- Process Image
- ParentImage
- ProcessId / ParentProcessId
- Process Tree
- Windows authentication events
- Network telemetry
- Severity classification
- False positive analysis

---

## SOC Investigation Methodology

Pour chaque alerte, l'investigation suit une approche structurée :

1. Identifier l'événement.
2. Analyser le processus ou l'utilisateur concerné.
3. Examiner la CommandLine.
4. Reconstruire le Process Tree lorsque nécessaire.
5. Vérifier l'activité réseau associée.
6. Rechercher des indicateurs de compromission.
7. Évaluer les faux positifs.
8. Mapper l'activité à MITRE ATT&CK.
9. Déterminer la sévérité.
10. Produire un verdict final.

---

## MITRE ATT&CK

Le laboratoire utilise MITRE ATT&CK pour contextualiser les comportements observés.

Exemples :

- **T1059.001 — PowerShell**
- **T1218.011 — Rundll32**

Le mapping MITRE est utilisé comme contexte de détection et ne constitue pas, à lui seul, une preuve de compromission.

---

## EDR-Style Analysis

Le projet reproduit également certaines capacités d'une solution EDR :

**Process Monitoring**
→ **Parent/Child Analysis**
→ **CommandLine Analysis**
→ **Network Investigation**
→ **Detection**
→ **Triage**
→ **Investigation**
→ **Response Decision**

L'objectif est de développer une méthodologie applicable aux environnements SOC utilisant des solutions SIEM/EDR.

---

## Compétences démontrées

### SOC / Blue Team

- Alert Triage
- Security Monitoring
- Incident Investigation
- False Positive Analysis
- Detection Engineering
- Process Analysis
- Windows Authentication Analysis
- Network Investigation
- MITRE ATT&CK Mapping

### Technologies

- Windows 11
- Sysmon
- Splunk Enterprise
- PowerShell
- Windows Security Logs
- SPL

---

## Résultats

Le laboratoire permet de démontrer une capacité à :

- Collecter de la télémétrie endpoint.
- Construire des règles de détection Splunk.
- Analyser des événements Windows.
- Investiguer des processus et Process Trees.
- Corréler plusieurs sources de télémétrie.
- Identifier et réduire les faux positifs.
- Mapper les comportements à MITRE ATT&CK.
- Documenter une investigation SOC.
- Produire un verdict et une décision d'escalade.

---

## Environnement

Laboratoire personnel contrôlé à des fins d'apprentissage, de détection engineering et de démonstration de compétences SOC.

Aucune donnée sensible ou information réelle d'entreprise n'est volontairement publiée dans ce repository.

---

## Auteur

**Oussama Ismaili**

IT Administration & Security  
Focus: **SOC | SIEM | Windows Security | Detection Engineering**
