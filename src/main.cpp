#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/error.h"

BLEServer *pServer = NULL;
BLECharacteristic *pTxCharacteristic;
bool deviceConnected = false;
bool newMessageAvailable = false;
std::string receivedMessage = "";

#define SERVICE_UUID "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define CHARACTERISTIC_UUID_RX "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
#define CHARACTERISTIC_UUID_TX "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

void print_error(int ret) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    Serial.print("Error: ");
    Serial.println(error_buf);
}

void sha256_hash(const std::string &input, unsigned char output[32]) {
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts_ret(&sha_ctx, 0);
    mbedtls_sha256_update_ret(&sha_ctx, (const unsigned char *)input.c_str(), input.length());
    mbedtls_sha256_finish_ret(&sha_ctx, output);
    mbedtls_sha256_free(&sha_ctx);
}

void aes_encrypt(const std::string &input, const unsigned char key[32], unsigned char iv[16], unsigned char output[128]) {
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, key, 256);
    size_t input_len = input.length();
    size_t output_len = ((input_len + 15) / 16) * 16; // Pad to the next multiple of 16
    unsigned char input_padded[128];
    memset(input_padded, 0, 128);
    memcpy(input_padded, input.c_str(), input_len);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, output_len, iv, input_padded, output);
    mbedtls_aes_free(&aes_ctx);
}

class MyBLECallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pCharacteristic) {
        receivedMessage = pCharacteristic->getValue();
        newMessageAvailable = true;
    }
};

void setup() {
    Serial.begin(115200);

    BLEDevice::init("ESP32 BLE");
    pServer = BLEDevice::createServer();
    BLEService *pService = pServer->createService(SERVICE_UUID);
    pTxCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_UUID_TX,
        BLECharacteristic::PROPERTY_NOTIFY
    );
    pTxCharacteristic->addDescriptor(new BLE2902());

    BLECharacteristic *pRxCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_UUID_RX,
        BLECharacteristic::PROPERTY_WRITE
    );

    pRxCharacteristic->setCallbacks(new MyBLECallbacks());

    pService->start();
    pServer->getAdvertising()->start();
    Serial.println("Waiting for a client connection to notify...");

    Serial.println("Enter text to hash and encrypt via Serial or BLE:");
}

void loop() {
    if (Serial.available()) {
        receivedMessage = Serial.readStringUntil('\n').c_str();
        newMessageAvailable = true;
    }

    if (newMessageAvailable) {
        newMessageAvailable = false;

        // Compute SHA-256 hash
        unsigned char hash[32];
        sha256_hash(receivedMessage, hash);
        Serial.print("SHA-256 Hash: ");
        for (int i = 0; i < 32; i++) {
            Serial.printf("%02x", hash[i]);
        }
        Serial.println();

        // AES Encryption
        const unsigned char key[32] = "this_is_a_very_secure_key_32by"; // 256-bit key
        unsigned char iv[16] = {0}; // Initialization vector (all zeroes for simplicity)
        unsigned char encrypted[128];

        aes_encrypt(receivedMessage, key, iv, encrypted);
        Serial.print("AES Encrypted: ");
        for (size_t i = 0; i < 128; i++) {
            Serial.printf("%02x", encrypted[i]);
        }
        Serial.println();

        // Notify via BLE if connected
        if (deviceConnected) {
            std::string encryptedMessage(reinterpret_cast<char*>(encrypted), 128);
            pTxCharacteristic->setValue(encryptedMessage);
            pTxCharacteristic->notify();
        }
    }
}
