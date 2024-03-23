#include <stdio.h>
#include <openssl/rand.h>

#define KEY_LENGTH 32

int main() {
    unsigned char key[KEY_LENGTH];

    // Generate random key
    if (RAND_bytes(key, KEY_LENGTH) != 1) {
        fprintf(stderr, "Error generating random key\n");
        return 1;
    }

    // Print the random key
    printf("Random Key: ");
    for (int i = 0; i < KEY_LENGTH; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}
