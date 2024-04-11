#include "SPI.h"
#include "MFRC522.h"

#define RST_PIN  9 // Pin RST
#define SS_PIN  10 // Pin SDA (SS)

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

long int start_time;

void updateBalance(float amount);
void showCurrentBalance();
void resetAndFormatMemory();
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
    Serial.println(F("'reset' pour supprimer le crédit et mettre à 0"));

    // Initialiser la clé de sécurité par défaut pour l'authentification
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }
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
        showCurrentBalance();
        return;
      } else if (commandLine == "reset") {
        resetAndFormatMemory();
        return;
      }
      int index = commandLine.indexOf(' ');
      if (index != -1) {
        String command = commandLine.substring(0, index);
        String numberString = commandLine.substring(index + 1);
        float amount = numberString.toFloat();

        if (command == "add" && amount > 0) {
          start_time = millis();
          updateBalance(amount);
          Serial.print(F("Temps d'exécution de la commande: "));
          Serial.print(millis() - start_time);
          Serial.println(F(" ms"));
        } else if (command == "remove" && amount > 0) {
          start_time = millis();
          updateBalance(-amount);
          Serial.print(F("Temps d'exécution de la commande: "));
          Serial.print(millis() - start_time);
          Serial.println(F(" ms"));
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
    byte block = 1; // Le bloc où le solde est stocké
    byte buffer[18];
    byte size = sizeof(buffer);
    float currentBalance = 0;

    // Authentifier le bloc
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Authentification échouée: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Lire le solde actuel
    status = mfrc522.MIFARE_Read(block, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Lecture échouée: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Convertir les 4 premiers octets en un float
    memcpy(&currentBalance, buffer, sizeof(currentBalance));

    // Mettre à jour le solde
    currentBalance += amount;
    if (currentBalance < 0) {
        Serial.println(F("Crédit insuffisant."));
        return;
    }

    // Convertir le nouveau solde en octets et écrire sur le badge
    memcpy(buffer, &currentBalance, sizeof(currentBalance));
    status = mfrc522.MIFARE_Write(block, buffer, 16); // 16 est la taille standard d'un bloc
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    Serial.print(F("Nouveau solde: "));
    Serial.println(currentBalance, 2);
}

void showCurrentBalance() {
    byte block = 1; // Le bloc où le solde est stocké
    byte buffer[18];
    byte size = sizeof(buffer);
    float currentBalance = 0;

    // Authentifier le bloc
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Erreur d'authentification: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Lire le solde actuel
    status = mfrc522.MIFARE_Read(block, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Erreur de lecture: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Convertir les 4 premiers octets en un float
    memcpy(&currentBalance, buffer, sizeof(currentBalance));
    Serial.print(F("Solde actuel: "));
    Serial.println(currentBalance, 2);
}

void resetAndFormatMemory() {
    // Définir les blocs à réinitialiser
    byte blocksToReset[] = {1, 2};
    byte zeroBuffer[16]; // Buffer de 16 zéros pour la réinitialisation des blocs
    memset(zeroBuffer, 0, sizeof(zeroBuffer)); // Remplir le buffer avec des zéros

    for (unsigned int i = 0; i < sizeof(blocksToReset); i++) {
        byte block = blocksToReset[i];

        // Authentifier le bloc
        MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("Erreur d'authentification pour le bloc "));
            Serial.print(block);
            Serial.print(F(": "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            continue; // Passer au bloc suivant en cas d'échec
        }

        // Écrire des zéros dans le bloc
        status = mfrc522.MIFARE_Write(block, zeroBuffer, 16); // 16 est la taille standard d'un bloc
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("Erreur d'écriture pour le bloc "));
            Serial.print(block);
            Serial.print(F(": "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            continue; // Passer au bloc suivant en cas d'échec
        }
    }

    Serial.println(F("Blocs réinitialisés et formatés avec des zéros."));
}

void setBalance(float amount) {
    if (amount < 0) {
        Serial.println(F("Le montant ne peut pas être négatif."));
        return;
    }

    byte block = 1; // Le bloc où le solde sera stocké
    byte buffer[18]; // Un buffer pour contenir les données à écrire, plus grand que nécessaire
    byte size = sizeof(float); // La taille du type float

    // Préparation des données à écrire : convertir le montant en octets
    memcpy(buffer, &amount, size);

    // Authentifier le bloc avant l'écriture
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Authentification échouée pour le bloc "));
        Serial.print(block);
        Serial.print(F(": "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Écrire le solde sur le badge
    status = mfrc522.MIFARE_Write(block, buffer, 16); // 16 est la taille d'un bloc standard sur MIFARE Classic
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Écriture échouée pour le bloc "));
        Serial.print(block);
        Serial.print(F(": "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    Serial.print(F("Solde défini à: "));
    Serial.println(amount, 2);
}
