#include <Arduino.h>
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

void setup() {
    Serial.begin(115200);
    Serial.println("SHA example: ");
    const char *data = "Hello, hardware SHA!";
    unsigned char sha256_result[32];

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const unsigned char *)data, strlen(data));
    mbedtls_sha256_finish_ret(&ctx, sha256_result);
    mbedtls_sha256_free(&ctx);

    Serial.println("SHA-256 result:");
    for (int i = 0; i < 32; i++) {
        Serial.printf("%02x", sha256_result[i]);
    }
    Serial.println();

        const char *plain_text = "This is a test.";
    unsigned char key[16] = {0}; // 128-bit key
    unsigned char iv[16] = {0};  // IV should be unique for each encryption
    unsigned char cipher_text[16];
    unsigned char decrypted_text[16];

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    // Encryption
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, (const unsigned char *)plain_text, cipher_text);

    Serial.println("Cipher text:");
    for (int i = 0; i < 16; i++) {
        Serial.printf("%02x", cipher_text[i]);
    }
    Serial.println();
    Serial.println("AES example: ");
    // Reset IV for decryption
    memset(iv, 0, 16);

    // Decryption
    mbedtls_aes_setkey_dec(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, cipher_text, decrypted_text);

    Serial.print("Decrypted text: ");
    Serial.println((char *)decrypted_text);

    mbedtls_aes_free(&aes);
}

void loop() {
    // put your main code here, to run repeatedly:
}
