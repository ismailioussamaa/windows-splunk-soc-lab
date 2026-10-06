# INC-002 — Investigation d'une connexion réseau

## 1. Résumé

Une activité réseau a été observée sur un endpoint Windows à partir du processus `microsip.exe`.

L'objectif de l'investigation est de déterminer si cette connexion correspond à une activité réseau légitime ou à une activité potentiellement malveillante.

---

## 2. Source de données

- **Source :** Sysmon
- **Event ID :** 3 — Network Connection
- **SIEM :** Splunk Enterprise
- **Endpoint :** Windows 11
- **Utilisateur observé :** `LAB\Administrator`
- ---

## 3. Connexion observée

Une connexion réseau a été observée depuis le processus `microsip.exe`.

Pour protéger les informations de l'environnement réel, les adresses IP sont anonymisées dans cette documentation.

| Élément | Valeur |
|---|---|
| Processus | `microsip.exe` |
| Protocole | UDP |
| Port destination | `5060` |
| Adresse source | `192.168.1.10` *(anonymisée)* |
| Adresse destination | `192.168.1.20` *(anonymisée)* |
---

## 4. Analyse

Le processus `microsip.exe` a établi une connexion UDP vers le port `5060`.

Le port UDP `5060` est couramment utilisé par le protocole SIP pour la signalisation de communications VoIP.

Dans ce contexte, la présence de `microsip.exe` et d'une connexion vers le port `5060` peut donc correspondre à une activité légitime.

Cependant, une analyse SOC doit vérifier le contexte de la connexion avant de conclure qu'elle est bénigne.


## 5. Vérifications SOC

Les vérifications suivantes ont été réalisées afin d'évaluer le contexte de la connexion :

- Vérification du processus à l'origine de la connexion.
- Vérification du protocole et du port utilisés.
- Vérification des événements Sysmon Event ID 3.
- Vérification de l'activité réseau associée au processus `microsip.exe`.
- Vérification de la cohérence entre l'application observée et le port utilisé.

Ces éléments permettent de déterminer si la connexion correspond à un comportement attendu ou si une investigation complémentaire est nécessaire.


## 6. Évaluation

**Verdict :** Activité probablement légitime.

**Sévérité :** Faible

### Justification

- `microsip.exe` est cohérent avec une application de communication VoIP.
- Le port UDP `5060` est cohérent avec le protocole SIP.
- Aucun indicateur de compromission n'a été identifié dans les éléments analysés.
- Les adresses IP sont anonymisées dans cette documentation.
- ---

## 7. Conclusion

L'activité réseau observée est cohérente avec l'utilisation légitime de `microsip.exe` pour des communications VoIP.

Aucun élément analysé ne permet de confirmer une activité malveillante.

L'alerte est donc classée comme **faible risque / activité légitime**.

**Statut :** Closed — Benign / Legitimate Activity
