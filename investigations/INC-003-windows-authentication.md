# INC-003 — Investigation d'une activité d'authentification Windows

## 1. Résumé

Une activité d'authentification Windows a été étudiée sur un endpoint de laboratoire.

L'objectif de l'investigation est de déterminer si les tentatives d'authentification correspondent à une activité légitime ou à un comportement potentiellement suspect.

Cette investigation se concentre principalement sur les événements Windows Security Event ID 4625 et 4624.

---

## 2. Source de données

- **Source :** Windows Security Event Log
- **Event ID :** 4625 — Failed Logon
- **Event ID :** 4624 — Successful Logon
- **SIEM :** Splunk Enterprise
- **Endpoint :** Windows 11
- **Utilisateur de laboratoire :** `LAB\Administrator`

---

## 3. Méthodologie d'investigation

L'analyse d'une activité d'authentification Windows doit prendre en compte plusieurs éléments :

1. Le nombre de tentatives d'authentification échouées.
2. La période pendant laquelle les tentatives ont eu lieu.
3. Le compte ciblé.
4. Le type de connexion utilisé.
5. La source de la tentative d'authentification.
6. La présence éventuelle d'une authentification réussie après plusieurs échecs.
7. Le contexte utilisateur et système.

Une succession de plusieurs échecs suivie d'une authentification réussie peut nécessiter une investigation complémentaire.

---

## 4. Événements Windows observés

### Event ID 4625 — Failed Logon

L'Event ID 4625 indique qu'une tentative d'ouverture de session Windows a échoué.

Les informations importantes à examiner comprennent notamment :

- Le compte ciblé.
- Le type de connexion (`Logon Type`).
- La source de la tentative.
- L'adresse IP source lorsqu'elle est disponible.
- Le processus ou service impliqué.
- L'heure de l'événement.

### Event ID 4624 — Successful Logon

L'Event ID 4624 indique qu'une authentification Windows a réussi.

Dans une investigation SOC, cet événement peut être corrélé avec des événements 4625 précédents afin de déterminer si une série d'échecs a été suivie d'une authentification réussie.

---

## 5. Analyse du scénario

Dans ce scénario de laboratoire, plusieurs tentatives d'authentification échouées peuvent être recherchées avant une éventuelle authentification réussie.

Une séquence de type `4625 → 4625 → 4625 → 4624` peut avoir plusieurs explications :

- Erreur de mot de passe.
- Problème de configuration.
- Tentative de brute force.
- Password spraying.
- Utilisation d'identifiants compromis.

La séquence seule ne permet donc pas de confirmer une compromission.

Le contexte de l'utilisateur, du poste, de la source et du type de connexion doit être analysé avant de prendre une décision.

---

## 6. Vérifications SOC

Les vérifications suivantes doivent être réalisées :

- Identifier le compte ciblé.
- Vérifier le nombre de tentatives échouées.
- Examiner les heures des événements.
- Vérifier le `Logon Type`.
- Identifier la source de la tentative lorsqu'elle est disponible.
- Rechercher une authentification réussie après plusieurs échecs.
- Vérifier si le comportement est habituel pour l'utilisateur.
- Rechercher d'autres événements suspects associés au même compte ou endpoint.

---

## 7. Détection Splunk

Une recherche Splunk simple peut être utilisée pour identifier les événements 4625 et 4624 :

```spl
index=main sourcetype="WinEventLog:Security"
(EventCode=4625 OR EventCode=4624)
| stats count by EventCode, Account_Name, Logon_Type, src_ip
| sort - count
```

Cette recherche permet d'obtenir une première vue des événements d'authentification.

Une investigation plus approfondie doit ensuite être réalisée sur les événements individuels.

---

## 8. Évaluation

**Verdict :** À déterminer selon le contexte.

**Sévérité initiale :** Low / Medium

### Éléments pouvant augmenter la sévérité

- Nombre important d'échecs d'authentification.
- Plusieurs comptes ciblés depuis une même source.
- Authentification réussie après une série d'échecs.
- Compte privilégié ciblé.
- Source inhabituelle.
- Activité en dehors des horaires habituels.
- Autres indicateurs suspects associés au compte ou à l'endpoint.

### Éléments pouvant indiquer une activité légitime

- Quelques erreurs de mot de passe seulement.
- Source connue et habituelle.
- Utilisateur identifié.
- Activité correspondant aux habitudes normales.
- Absence d'autres indicateurs de compromission.

---

## 9. Conclusion

L'analyse des événements Windows 4625 et 4624 permet d'identifier des comportements d'authentification potentiellement suspects.

Cependant, plusieurs échecs d'authentification ne suffisent pas à confirmer une attaque.

La corrélation entre les événements, l'analyse du contexte utilisateur, la source de connexion et les autres événements de sécurité sont nécessaires pour qualifier correctement l'alerte.

Dans un environnement SOC, une activité réellement suspecte devrait être escaladée conformément au playbook d'incident.

**Statut :** Investigation / À qualifier

---

## 10. SOC Response Workflow

### Triage

- Vérifier le compte ciblé.
- Vérifier le nombre de tentatives d'authentification échouées.
- Examiner le `Logon Type`.
- Identifier la source de la tentative lorsqu'elle est disponible.
- Rechercher une authentification réussie après plusieurs échecs.

### Investigation

- Analyser les événements 4625 et 4624.
- Vérifier la chronologie des événements.
- Identifier les comptes et sources concernés.
- Rechercher d'autres activités suspectes associées au compte ou à l'endpoint.
- Évaluer si le comportement correspond aux habitudes normales.

### Response Decision

La séquence d'authentification doit être évaluée selon son contexte.

- **Containment :** Selon le niveau de risque
- **Escalation :** Si des indicateurs de compromission sont confirmés
- **Action :** Surveiller, approfondir l'investigation ou escalader selon le verdict

### Closure

**Classification :** À qualifier selon le contexte

**Final Severity :** Low / Medium

**Status :** Investigation / À qualifier
