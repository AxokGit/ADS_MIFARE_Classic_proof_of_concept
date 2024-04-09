# ADS : MIFARE Classic : Proof of concept

Dans ce dépot se trouve 4 codes Arduino en C++ démontrant la faisabilité de la solution présenté dans mon ADS.

## Commun à tous les codes:

### Prérequis

Pour mettre en place la solution, le matériel nécessaire est le suivant:
- Arduino Uno
- Lecteur RFID-RC522
- 7 fils jumper
- Badges MIFARE Classic

### Fonctionnement:

Le code utilise l'interface série avec un baudrate de 115200 pour recevoir des commandes et envoyer des informations.

Selon les codes, différentes commandes existent.

### Limitations:

Ces codes étant des preuves de concept, il n'intègre pas toutes les fonctionnalités nécessaires d'un système de crédit complet:

- Le système ne fonctionne qu'avec un seul badge
- Le système n'utilise pas les clés Crypto1 du badge MIFARE Classic pour limiter l'accès à la mémoire
- Le système ne fait aucune journalisation stockée dans une mémoire permanente

## Code n°1: Full_System_No_Encryption

Ce code fait référence aux systèmes actuels. Il utilise un badge MIFARE Classic pour stocker un crédit dans la mémoire pour un paiement auprès de plusieurs machines.

## Code N°2: Full_System_With_Encrpytion

Ce code permet d'empecher la modification de la mémoire en chiffrant les données en utilisant AES128. La clé de chiffrement est stocké en brut dans une variable appelé aesKey.
Il permet de stocker le crédit dans le secteur 0 du badge, plus précisément le bloc 1 et 2 de la mémoire, soit 32 octets.

## Code n°3: Full_System_With_TOTP

Ce permet présente la solution contre le clonage. Il se base sur un code TOTP inscrit dans la mémoire du badge ainsi que le temps Unix du code. Le lecteur ayant le jeton d'authentification TOTP pourra vérifier la validité du code à l'aide du temps Unix. Il placera chacun code unique dans une liste noire pour détecter le clonage

## Code n°4: Full_System_With_Encryption_TOTP

Ce code combine le code n°2 et n°3 en un seul système pour prouver que les 2 solutions peuvent fonctionner ensemble