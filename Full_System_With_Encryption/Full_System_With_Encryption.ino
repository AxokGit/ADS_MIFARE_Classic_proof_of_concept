#include "SPI.h"
#include "MFRC522.h"
#include <Crypto.h>
#include <AES.h>
#include "CRC32.h"

#define RST_PIN  9 // Pin RST
#define SS_PIN  10 // Pin SDA (SS)

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

AES128 aes128;
uint8_t aesKey[16] = { 0x28, 0x3C, 0x1D, 0x3B, 0x46, 0x1F, 0x52, 0x5A, 0x5F, 0x18, 0x0E, 0x5C, 0x15, 0x2F, 0x52, 0x40 };
CRC32 crc;

void updateBalance(float amount);
void showCurrentBalance();
void setBalance(float amount);

void setup() {
    Serial.begin(115200);
    SPI.begin();
    mfrc522.PCD_Init();
    delay(4);
    
    Serial.println(F("'info' pour lire le crédit"));
    Serial.println(F("'add XX.XX' pour ajouter du crédit"));
    Serial.println(F("'remove XX.XX' pour retirer du crédit"));
    Serial.println(F("'set XX.XX' pour définir du crédit"));

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
      Serial.println();
      Serial.print("Commande reçue: ");
      Serial.println(commandLine);
      if (commandLine == "info") {
        if (!verifyBalanceCRC()){
          Serial.println("Test CRC échoué. Badge corrompu");
          return;
        }
        showCurrentBalance();
        return;
      }
      int index = commandLine.indexOf(' ');
      if (index != -1) {
        String command = commandLine.substring(0, index);
        String numberString = commandLine.substring(index + 1);
        float amount = numberString.toFloat();

        if (command == "add" && amount > 0) {
          if (!verifyBalanceCRC()){
            Serial.println("Test CRC échoué. Badge corrompu");
            return;
          }
          updateBalance(amount);
        } else if (command == "remove" && amount > 0) {
          if (!verifyBalanceCRC()){
            Serial.println("Test CRC échoué. Badge corrompu");
            return;
          }
          updateBalance(-amount);
        } else if (command == "set" && amount >= 0) {
          setBalance(amount);
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
    byte block1 = 1;
    byte block2 = 2;
    byte buffer[32]; // Assurez-vous que la taille du buffer est suffisante pour le solde et le CRC
    byte size = sizeof(buffer);
    byte encryptedBuffer1[16], encryptedBuffer2[16];
    float currentBalance = 0;
    CRC32 crc;

    memset(buffer, 0, sizeof(buffer));

    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block1, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Authentification échouée: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    status = mfrc522.MIFARE_Read(block1, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Lecture échouée: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    aes128.decryptBlock(encryptedBuffer1, buffer);
    memcpy(&currentBalance, encryptedBuffer1, sizeof(currentBalance));

    currentBalance += amount;
    if (currentBalance < 0) {
        Serial.println(F("Crédit insuffisant."));
        return;
    }

    memcpy(buffer, &currentBalance, sizeof(currentBalance));

    // Réinitialiser l'objet CRC pour le nouveau calcul
    crc.reset();

    // Ajouter les octets du nouveau solde au calcul du CRC
    uint8_t* balanceBytes = reinterpret_cast<uint8_t*>(&currentBalance);
    for (size_t i = 0; i < sizeof(currentBalance); ++i) {
        crc.add(balanceBytes[i]);
    }

    // Calculer le CRC
    uint32_t crcValue = crc.calc();
    // Stocker le CRC dans le buffer, juste après le solde
    memcpy(buffer + sizeof(currentBalance), &crcValue, sizeof(crcValue));

    // Chiffrer le buffer en deux parties
    aes128.encryptBlock(encryptedBuffer1, buffer); // Première moitié
    aes128.encryptBlock(encryptedBuffer2, buffer + 16); // Seconde moitié

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
    byte block1 = 1;
    byte block2 = 2;
    byte buffer[32]; // Assurez-vous que la taille du buffer est suffisante pour le solde et le CRC
    byte encryptedBuffer1[16], encryptedBuffer2[16]; // Buffers pour les données chiffrées

    // Initialisation du buffer à 0
    memset(buffer, 0, sizeof(buffer));
    // Copie du montant dans le buffer
    memcpy(buffer, &amount, sizeof(amount));

    crc.reset();

    // Ajouter les octets du montant au calcul du CRC
    uint8_t* amountBytes = reinterpret_cast<uint8_t*>(&amount);
    for (size_t i = 0; i < sizeof(amount); ++i) {
        crc.add(amountBytes[i]);
    }

    // Calculer le CRC
    uint32_t crcValue = crc.calc();
    // Stocker le CRC dans le buffer, juste après le montant
    memcpy(buffer + sizeof(amount), &crcValue, sizeof(crcValue));

    // Chiffrer le buffer en deux parties
    aes128.encryptBlock(encryptedBuffer1, buffer); // Première moitié
    aes128.encryptBlock(encryptedBuffer2, buffer + 16); // Seconde moitié

    // Authentifier et écrire le premier bloc chiffré sur la carte
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block1, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Authentification échouée pour le bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    status = mfrc522.MIFARE_Write(block1, encryptedBuffer1, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée pour le bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Écrire le second bloc chiffré sur la carte
    status = mfrc522.MIFARE_Write(block2, encryptedBuffer2, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée pour le bloc 2: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    Serial.print(F("Solde défini à: "));
    Serial.println(amount, 2);
}

bool verifyBalanceCRC() {
    byte block1 = 1;
    byte block2 = 2;
    byte buffer1[18], buffer2[18]; // Buffers pour lire les données chiffrées
    byte decryptedBuffer[32]; // Buffer pour les données déchiffrées
    byte size = 18;
    float balance;
    uint32_t storedCRC, calculatedCRC;

    // Authentifier et lire le premier bloc
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block1, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Authentification échouée pour le bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }
    status = mfrc522.MIFARE_Read(block1, buffer1, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Lecture échouée pour le bloc 1: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }

    // Lire le second bloc (l'authentification du premier bloc reste valide)
    status = mfrc522.MIFARE_Read(block2, buffer2, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Lecture échouée pour le bloc 2: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }

    // Déchiffrer les données
    aes128.decryptBlock(decryptedBuffer, buffer1);
    aes128.decryptBlock(decryptedBuffer + 16, buffer2);

    // Extraire le solde et le CRC stocké
    memcpy(&balance, decryptedBuffer, sizeof(balance));
    memcpy(&storedCRC, decryptedBuffer + sizeof(balance), sizeof(storedCRC));

    // Calculer le CRC du solde déchiffré
    crc.reset();
    uint8_t* balanceBytes = reinterpret_cast<uint8_t*>(&balance);
    for (size_t i = 0; i < sizeof(balance); i++) {
        crc.add(balanceBytes[i]);
    }
    calculatedCRC = crc.calc();

    // Comparer le CRC stocké au CRC calculé
    if (calculatedCRC == storedCRC) {
        return true;
    } else {
        return false;
    }
}
