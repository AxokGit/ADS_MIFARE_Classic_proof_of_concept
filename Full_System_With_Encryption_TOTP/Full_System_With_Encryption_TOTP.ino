#include "SPI.h"
#include "MFRC522.h"
#include <Crypto.h>
#include <AES.h>
#include <TOTP.h>

#define RST_PIN  9 // Pin RST
#define SS_PIN  10 // Pin SDA (SS)

const char* secretKey = "JBSWY3DPEHPK3PXP";
const unsigned long initialUnixTime = 1712646794;
String blacklist[50]; // Ajustez la taille selon vos besoins
int blacklistCount = 0;

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;
TOTP totp = TOTP((uint8_t*)secretKey, strlen(secretKey), 6);

AES128 aes128;
uint8_t aesKey[16] = { 0x28, 0x3C, 0x1D, 0x3B, 0x46, 0x1F, 0x52, 0x5A, 0x5F, 0x18, 0x0E, 0x5C, 0x15, 0x2F, 0x52, 0x40 };

void updateBalance(float amount);
void showCurrentBalance();
void setBalance(float amount);
bool checkAndUpdateTOTP();
void initializeBadge();

void setup() {
    Serial.begin(115200);
    SPI.begin();
    mfrc522.PCD_Init();
    delay(4);
    
    Serial.println(F("'info' pour lire le crédit"));
    Serial.println(F("'add XX.XX' pour ajouter du crédit"));
    Serial.println(F("'remove XX.XX' pour retirer du crédit"));
    Serial.println(F("'set XX.XX' pour définir du crédit"));
    Serial.println(F("'init_totp' pour initialiser la sécurité TOTP"));

    // Initialiser la clé de sécurité par défaut pour l'authentification
    for (byte i = 0; i < 6; i++) {
      key.keyByte[i] = 0xFF;
    }
    aes128.setKey(aesKey, sizeof(aesKey));
}

void loop() {
  // Vérifiez si une carte est présente
  if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
    // Vérifier si une commande est reçue via le port série
    if (Serial.available() > 0) {
      String commandLine = Serial.readStringUntil('\n');
      Serial.println(commandLine);
      if (commandLine == "info") {
        showCurrentBalance();
        return;
      } else if (commandLine == "reset") {
        return;
      } else if (commandLine == "init_totp") {
        initializeBadge();
        return;
      }
      int index = commandLine.indexOf(' ');
      if (index != -1) {
        String command = commandLine.substring(0, index);
        String numberString = commandLine.substring(index + 1);
        float amount = numberString.toFloat();

        if (command == "add" && amount > 0) {
          if (checkAndUpdateTOTP()){
            Serial.println("Vérification TOTP réussie !");
            updateBalance(amount);
          } else {
            Serial.println("Vérification TOTP échouée.");
          }
        } else if (command == "remove" && amount > 0) {
          if (checkAndUpdateTOTP()){
            Serial.println("Vérification TOTP réussie !");
            updateBalance(-amount);
          } else {
            Serial.println("Vérification TOTP échouée.");
          }
        } else if (command == "set" && amount >= 0) {
          if (checkAndUpdateTOTP()){
            Serial.println("Vérification TOTP réussie !");
            setBalance(amount);
          } else {
            Serial.println("Vérification TOTP échouée.");
          }
        } else {
            Serial.println(F("Commande non reconnue."));
        } 
      } else {
        Serial.println(F("Format de commande incorrect."));
      }
    }
  } else {
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
  }

  delay(200);
}


void updateBalance(float amount) {
    // Les blocs sur lesquels écrire le solde chiffré
    byte block1 = 1;
    byte block2 = 2;
    byte buffer[32]; // Buffer pour stocker le solde et le padding
    byte size = sizeof(buffer);
    byte encryptedBuffer1[16], encryptedBuffer2[16]; // Buffers pour les données chiffrées
    float currentBalance = 0;

    // Initialisation du buffer à 0
    memset(buffer, 0, sizeof(buffer));

    // Authentifier le premier bloc (pas nécessaire de le faire pour chaque bloc avec MIFARE Classic)
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block1, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Authentification échouée: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Lire le solde actuel du premier bloc, supposer qu'il est stocké dans le premier bloc chiffré
    status = mfrc522.MIFARE_Read(block1, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Lecture échouée: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Déchiffrer le premier bloc pour obtenir le solde actuel
    aes128.decryptBlock(encryptedBuffer1, buffer);
    memcpy(&currentBalance, encryptedBuffer1, sizeof(currentBalance));

    // Mettre à jour le solde
    currentBalance += amount;
    if (currentBalance < 0) {
        Serial.println(F("Crédit insuffisant."));
        return;
    }

    // Préparer le buffer avec le nouveau solde
    memcpy(buffer, &currentBalance, sizeof(currentBalance));

    // Chiffrer le buffer en deux parties
    aes128.encryptBlock(encryptedBuffer1, buffer); // Première moitié
    aes128.encryptBlock(encryptedBuffer2, buffer + 16); // Seconde moitié

    // Écrire les blocs chiffrés sur le badge
    status = mfrc522.MIFARE_Write(block1, encryptedBuffer1, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée pour le bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    status = mfrc522.MIFARE_Write(block2, encryptedBuffer2, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée pour le bloc 2: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    Serial.print(F("Nouveau solde: "));
    Serial.println(currentBalance, 2);
}


void showCurrentBalance() {
    byte block1 = 1;
    byte block2 = 2;
    byte buffer1[18], buffer2[18]; // Buffers pour lire les blocs chiffrés
    byte decryptedBuffer[32]; // Buffer pour les données déchiffrées, assez grand pour deux blocs
    byte size = 18; // Taille attendue pour la lecture, incluant 2 octets de CRC
    float currentBalance = 0;

    // Authentifier le premier bloc
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block1, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Erreur d'authentification: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Lire le premier bloc
    status = mfrc522.MIFARE_Read(block1, buffer1, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Erreur de lecture bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Lire le second bloc (la ré-authentification n'est pas nécessaire pour les blocs consécutifs)
    status = mfrc522.MIFARE_Read(block2, buffer2, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Erreur de lecture bloc 2: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Déchiffrer les blocs
    aes128.decryptBlock(decryptedBuffer, buffer1); // Déchiffrer le premier bloc
    aes128.decryptBlock(decryptedBuffer + 16, buffer2); // Déchiffrer le second bloc, ajouter au buffer déchiffré

    // Convertir les premiers 4 octets déchiffrés en un float pour obtenir le solde
    memcpy(&currentBalance, decryptedBuffer, sizeof(currentBalance));

    Serial.print(F("Solde actuel: "));
    Serial.println(currentBalance, 2);
}

void setBalance(float amount) {
    // Les blocs sur lesquels écrire le solde chiffré
    byte block1 = 1;
    byte block2 = 2;
    byte buffer[32]; // Tampon pour stocker le solde et le remplissage
    byte encryptedBuffer1[16], encryptedBuffer2[16]; // Buffers pour les données chiffrées
    byte size = 18; // La taille pour les opérations de lecture, bien que non utilisée ici

    // Vérifier si le montant est valide
    if (amount < 0) {
        Serial.println(F("Le montant ne peut pas être négatif."));
        return;
    }

    // Initialisation du buffer à 0 et copie du montant dans le buffer
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, &amount, sizeof(amount));

    // Chiffrer le buffer en deux parties
    aes128.encryptBlock(encryptedBuffer1, buffer); // Première moitié
    aes128.encryptBlock(encryptedBuffer2, buffer + 16); // Seconde moitié

    // Authentifier le premier bloc
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block1, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Authentification échouée pour le bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Écrire le premier bloc chiffré sur la carte
    status = mfrc522.MIFARE_Write(block1, encryptedBuffer1, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée pour le bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Écrire le second bloc chiffré sur la carte (l'authentification du bloc précédent reste valable)
    status = mfrc522.MIFARE_Write(block2, encryptedBuffer2, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée pour le bloc 2: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    Serial.print(F("Solde défini à: "));
    Serial.println(amount, 2);
}

bool checkAndUpdateTOTP() {
  byte blockTOTP = 4; // Bloc pour le stockage du TOTP
  byte blockUnixTime = 5; // Bloc pour le stockage du temps Unix
  byte buffer[18]; // Buffer pour la lecture/écriture des données
  byte size = sizeof(buffer);
  unsigned long currentUnixTime;
  char currentTOTP[10]; // Assurez-vous que la taille du tableau peut contenir le TOTP plus un caractère nul de fin

  // Authentifier et lire le temps Unix depuis le badge
  MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockUnixTime, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Erreur d'authentification pour le temps Unix: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  status = mfrc522.MIFARE_Read(blockUnixTime, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Erreur de lecture du temps Unix: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  // Copier le temps Unix lu dans currentUnixTime
  memcpy(&currentUnixTime, buffer, sizeof(currentUnixTime));

  // Authentifier et lire le TOTP depuis le badge
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockTOTP, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Erreur d'authentification pour le TOTP: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  status = mfrc522.MIFARE_Read(blockTOTP, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Erreur de lecture du TOTP: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  // Copier le TOTP lu dans currentTOTP
  memcpy(currentTOTP, buffer, sizeof(currentTOTP) - 1); // Laisser un espace pour le caractère de fin
  currentTOTP[sizeof(currentTOTP) - 1] = '\0'; // S'assurer que la chaîne est terminée correctement

  Serial.print("currentTOTP: ");
  Serial.println(currentTOTP);

  for(int i = 0; i < blacklistCount; i++) {
    if(blacklist[i] == String(currentTOTP)) { // Utiliser la conversion String pour la comparaison si blacklist est un tableau de String
      Serial.println(F("Code TOTP dans la liste noire. Accès refusé."));
      return false; // Bloquer l'opération si le TOTP est dans la liste noire
    }
  }

  char* expectedTOTP = totp.getCode(currentUnixTime);

  Serial.print("expectedTOTP: ");
  Serial.println(expectedTOTP); 

  if (strcmp(currentTOTP, expectedTOTP) == 0) {
    // Le code TOTP est valide, préparer le nouveau TOTP et le temps Unix
    currentUnixTime += 30; // Ajouter 30 secondes pour le prochain code
    char* newTOTP = totp.getCode(currentUnixTime);

    // Écrire le nouveau temps Unix
    memcpy(buffer, &currentUnixTime, sizeof(currentUnixTime));
    status = mfrc522.MIFARE_Write(blockUnixTime, buffer, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("Écriture échouée pour le temps Unix: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
    }

    // Écrire le nouveau TOTP
    memset(buffer, 0, sizeof(buffer)); // Nettoyer le buffer
    strncpy((char *)buffer, newTOTP, sizeof(buffer) - 1); // Copier le nouveau TOTP dans le buffer, en laissant de la place pour le caractère nul
    buffer[sizeof(buffer) - 1] = '\0'; // S'assurer que le buffer est correctement terminé
    status = mfrc522.MIFARE_Write(blockTOTP, buffer, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("Écriture échouée pour le TOTP: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
    }

    if (blacklistCount < sizeof(blacklist) / sizeof(blacklist[0])) { // Utiliser la taille réelle de la liste
      blacklist[blacklistCount++] = String(currentTOTP);
    }

    return true;
  } else {
    return false;
  }
}

void initializeBadge() {
  byte blockTOTP = 4; // Bloc pour le stockage du code TOTP
  byte blockUnixTime = 5; // Bloc pour le stockage du temps Unix
  byte buffer[18]; // Buffer pour l'écriture des données
  MFRC522::StatusCode status;

  // Générer le premier code TOTP
  char* initialTOTP = totp.getCode(initialUnixTime);

  // Authentifier et écrire le temps Unix sur le badge
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockUnixTime, &key, &(mfrc522.uid));
  if (status == MFRC522::STATUS_OK) {
    memcpy(buffer, &initialUnixTime, sizeof(initialUnixTime));
    status = mfrc522.MIFARE_Write(blockUnixTime, buffer, 16); // 16 est la taille standard d'un bloc
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("Écriture échouée pour le temps Unix: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
    } else {
      Serial.println("Écriture réussie pour le temps Unix");
    }
  } else {
    Serial.print(F("Authentification échouée pour le bloc Unix: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }

  // Authentifier et écrire le TOTP sur le badge
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockTOTP, &key, &(mfrc522.uid));
  if (status == MFRC522::STATUS_OK) {
    memset(buffer, 0, sizeof(buffer)); // Nettoyer le buffer
    strncpy((char *)buffer, initialTOTP, sizeof(buffer) - 1); // S'assurer que le buffer est correctement terminé
    buffer[sizeof(buffer) - 1] = '\0'; // Ajouter le caractère de fin si nécessaire
    status = mfrc522.MIFARE_Write(blockTOTP, buffer, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("Écriture échouée pour le TOTP: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
    } else {
      Serial.println("Écriture réussie pour le TOTP");
    }
  } else {
    Serial.print(F("Authentification échouée pour le bloc TOTP: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
}