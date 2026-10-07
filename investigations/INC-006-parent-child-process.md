# INC-006 — Parent → Child Process Investigation

## 1. Résumé

Une exécution PowerShell a été détectée sur un endpoint Windows et analysée avec Sysmon Event ID 1.

L'objectif était d'analyser la relation entre le processus parent et le processus enfant afin d'identifier un comportement potentiellement suspect.

---

## 2. Process Tree

explorer.exe
    ↓
powershell.exe
    ↓
powershell.exe

La relation `powershell.exe → powershell.exe` a été analysée avec la ligne de commande complète.

---

## 3. Commande observée

`powershell.exe -NoProfile -Command Write-Output "Invoke-WebRequest"`

La présence de `Invoke-WebRequest` a déclenché la détection.

Cependant, la commande utilise `Write-Output` et aucun téléchargement réel n'a été confirmé.

---

## 4. Analyse SOC

Les éléments suivants ont été vérifiés :

- Processus parent et processus enfant
- Process Tree
- Ligne de commande
- Activité réseau associée
- Indicateurs PowerShell suspects
- Contexte de l'exécution

Une vérification des événements Sysmon Event ID 3 n'a pas montré de connexion réseau associée à cette exécution de test.

---

## 5. Évaluation

**Verdict:** Benign / Lab Activity

**Severity:** Low / Medium

**Containment:** Not Required

**Escalation:** Not Required

L'activité correspond à un test de détection dans un environnement de laboratoire.

Aucun indicateur de compromission n'a été confirmé.

---

## 6. MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

PowerShell peut être utilisé légitimement ou dans le cadre d'une attaque.

Le contexte Parent → Child et l'analyse de la ligne de commande sont nécessaires pour qualifier correctement l'activité.

---

## 7. Conclusion

L'analyse de la relation Parent → Child permet d'ajouter du contexte aux détections endpoint et d'améliorer le triage SOC.

Dans ce scénario, l'activité a été classée comme légitime dans le contexte du laboratoire.

**Status:** Closed — Benign / Lab Activity
