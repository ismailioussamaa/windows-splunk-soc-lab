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
- **Utilisateur observé :** `OUSSAMA\Administrateur`

---

## 3. Commande observée

La commande suivante a été détectée :

```text
powershell.exe -NoProfile -Command Write-Output "Invoke-WebRequest"
