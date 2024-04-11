# ADS : MIFARE Classic : Proof of concept

Dans ce dépot se trouve 4 codes Arduino en C++ démontrant la faisabilité de la solution présentée dans mon ADS.

## Commun à tous les codes:

### Prérequis

Pour mettre en place la solution, le matériel nécessaire est le suivant:
- Arduino Uno
- Lecteur RFID-RC522
- 7 fils jumper
- Badges MIFARE Classic

![Branchement Arduino RC522](https://arduino-france.site/wp-content/uploads/2023/02/rfid-arduino.jpg)

### Fonctionnement:

Le code utilise l'interface série avec un baudrate de 115200 pour envoyer des commandes et recevoir des informations.

Selon les codes, différentes commandes existent.

### Limitations:

Ces codes étant des preuves de concept, ils n'intègrent pas toutes les fonctionnalités nécessaires d'un système complet de crédit :

- Le système ne fait pas de différence entre plusieurs badges
- Le système n'utilise pas les clés Crypto1 du badge MIFARE Classic pour limiter l'accès à la mémoire
- Le système ne fait aucune journalisation dans une mémoire permanente

## Code n°1: Full_System_No_Encryption

Ce code fait référence aux systèmes actuels. Il utilise un badge MIFARE Classic pour stocker un crédit dans la mémoire pour un paiement auprès de plusieurs machines.

## Code N°2: Full_System_With_Encrpytion

Ce code permet d'empêcher la modification de la mémoire en chiffrant les données en utilisant AES128. La clé de chiffrement est stockée en brut dans une variable appelé aesKey. Un contrôle CRC est utilisé pour vérifier l'intégrité des données.
Il permet de stocker le crédit dans le secteur 0 du badge, plus précisément le bloc 1 et 2 de la mémoire, soit sur 32 octets.

## Code n°3: Full_System_With_TOTP

Ce code permet présente la solution contre le clonage. Il se base sur un code TOTP inscrit dans la mémoire du badge ainsi que le temps Unix du code. Le lecteur ayant le jeton d'authentification TOTP pourra vérifier la validité du code à l'aide du temps Unix. Il placera chacun code unique dans une liste noire pour détecter le clonage. Attention la liste noire est stockée dans la RAM : A chaque redémarrage, la liste est remise à zéro.

## Code n°4: Full_System_With_Encryption_TOTP

Ce code combine le code n°2 et n°3 en un seul système pour prouver que les 2 solutions peuvent fonctionner ensemble.