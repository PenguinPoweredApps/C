#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 256 // AES key size in bits
#define AES_BLOCK_SIZE 16 // AES block size in bytes

void handleErrors(void)
{
    fprintf(stderr, "Error occurred\n");
    exit(EXIT_FAILURE);
}

void encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char **ciphertext, int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE); // Allocate memory for ciphertext
    if (*ciphertext == NULL)
        handleErrors();

    int len;

    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1)
        handleErrors();
    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1)
        handleErrors();
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char **plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    *plaintext = malloc(ciphertext_len); // Allocate memory for plaintext
    if (*plaintext == NULL)
        handleErrors();

    int len;

    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1)
        handleErrors();
    *plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1)
        handleErrors();
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <message> <key>\n", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned char *message = (unsigned char *)argv[1];
    unsigned char *key = (unsigned char *)argv[2];

    int plaintext_len = strlen((char *)message);
    int ciphertext_len;

    unsigned char *ciphertext;
    unsigned char *decrypted_text;

    // Generate a secure random IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1)
        handleErrors();

    encrypt(message, plaintext_len, key, iv, &ciphertext, &ciphertext_len);
    printf("Encrypted: ");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    decrypt(ciphertext, ciphertext_len, key, iv, &decrypted_text, &plaintext_len);
    printf("Decrypted: %s\n", decrypted_text);

    free(ciphertext);
    free(decrypted_text);

    return 0;
}
