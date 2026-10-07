# INC-004 — Investigation d'une exécution LOLBin

## 1. Résumé

Une exécution de `rundll32.exe` a été détectée par une règle de détection LOLBin.

L'objectif de l'investigation est de déterminer si cette activité correspond à un comportement légitime de Windows ou à une utilisation potentiellement malveillante.

---

## 2. Source de données

- **Source :** Sysmon
- **Event ID :** 1 — Process Creation
- **SIEM :** Splunk Enterprise
- **Endpoint :** Windows 11

---

## 3. Activité observée

Le processus observé est :

`rundll32.exe`

La ligne de commande faisait référence à :

`PcaSvc.dll` et `PcaPatchSdbTask`

Le processus parent observé était :

`svchost.exe`

---

## 4. Process Tree

`svchost.exe → rundll32.exe → PcaSvc.dll / PcaPatchSdbTask`

Cette relation Parent/Child est cohérente avec une activité système Windows.

---

## 5. Analyse

`rundll32.exe` est un binaire Windows légitime qui peut également être détourné par un attaquant.

Dans ce cas, plusieurs éléments ont été vérifiés :

- Processus exécuté
- Processus parent
- CommandLine
- DLL utilisée
- Process Tree
- Répétition du comportement
- Contexte système

Le même comportement a été observé plusieurs fois avec un contexte similaire.

Aucun indicateur de compromission n'a été identifié.

---

## 6. Analyse du processus parent

Le processus parent est `svchost.exe`.

`svchost.exe` est un processus Windows légitime utilisé pour héberger différents services système.

Le contexte observé est cohérent avec une activité système Windows.

---

## 7. False Positive Analysis

Une détection basée uniquement sur `rundll32.exe` peut générer des faux positifs.

Le SOC Analyst doit donc analyser le contexte avant de qualifier l'alerte.

Les éléments importants sont :

- `ParentImage`
- `ParentCommandLine`
- `CommandLine`
- DLL utilisée
- Chemin du binaire
- Process Tree
- Activité réseau
- Fréquence d'exécution

**Principe SOC :**

> LOLBin détecté ≠ Compromission confirmée

---

## 8. MITRE ATT&CK

L'utilisation de `rundll32.exe` peut être associée à :

**T1218.011 — System Binary Proxy Execution: Rundll32**

La présence de `rundll32.exe` seule ne permet toutefois pas de confirmer une activité malveillante.

---

## 9. Amélioration de la détection

Une détection plus précise peut combiner plusieurs indicateurs :

`rundll32.exe + CommandLine suspecte + Parent inhabituel + DLL inhabituelle + Activité réseau suspecte`

Cette approche permet de réduire les faux positifs et d'améliorer la qualité des alertes SOC.

---

## 10. Verdict final

**Classification :** Benign / Legitimate Activity

**Severity :** Low

**Status :** Closed — Benign / Legitimate Activity

### Conclusion

L'exécution de `rundll32.exe` analysée est cohérente avec une activité système Windows légitime.

L'analyse du processus parent, de la CommandLine, de la DLL utilisée et du contexte d'exécution ne révèle aucun indicateur permettant de confirmer une compromission.

---

## 11. SOC Response Workflow

### Triage

- Vérifier le processus `rundll32.exe`.
- Examiner le `ParentImage`.
- Analyser la `CommandLine`.
- Identifier la DLL utilisée.
- Vérifier le chemin du binaire.

### Investigation

- Analyser le Process Tree.
- Vérifier si la DLL et la commande sont cohérentes avec une activité Windows légitime.
- Rechercher une activité réseau associée.
- Vérifier les exécutions similaires.
- Rechercher d'éventuels IOC.

### Response Decision

L'analyse du contexte indique une activité système Windows légitime.

- **Containment :** Non requis
- **Escalation :** Non requise
- **Action :** Documenter le faux positif et maintenir la surveillance

### Closure

**Classification :** Benign / Legitimate Activity

**Final Severity :** Low

**Status :** Closed — Benign / Legitimate Activity

Cette investigation démontre l'importance du contexte dans une détection EDR/SOC.

> Une détection n'est pas une preuve de compromission.
