# Windows PowerShell Detection & Investigation Lab

## Présentation

Ce projet présente la mise en place d'un laboratoire SOC basé sur Windows, Sysmon et Splunk Enterprise.

L'objectif est de collecter de la télémétrie endpoint, de détecter des activités PowerShell potentiellement suspectes, de réduire les faux positifs, d'analyser les relations entre processus et de documenter une investigation de sécurité.

Le laboratoire a été réalisé dans un environnement personnel contrôlé à des fins d'apprentissage et de démonstration des compétences SOC.

---

## Architecture du laboratoire

```text
Windows 11
    |
    | Sysmon
    |
    +-----------------------------+
    |                             |
    | Event ID 1                  | Event ID 3
    | Process Creation            | Network Connection
    |                             |
    +--------------+--------------+
                   |
                   v
            Splunk Enterprise
                   |
                   v
       Détection & Investigation
