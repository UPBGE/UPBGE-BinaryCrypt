#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

#define SALT_LEN 16
#define PASSWORD_STR ENCRYPTION_PASSWORD
static const uint8_t salt[] = { ENCRYPTION_SALT };

void derive_key(uint8_t *key_out) {
    for (int i = 0; i < 32; i++) {
        key_out[i] = (uint8_t)(PASSWORD_STR[i % strlen(PASSWORD_STR)] ^ salt[i % SALT_LEN]);
    }
}

void decrypt_file(const char *input, const char *output) {
    FILE *fin = fopen(input, "rb");
    if (!fin) return;
    fseek(fin, 0, SEEK_END);
    long len = ftell(fin);
    rewind(fin);

    uint8_t *buffer = malloc(len);
    fread(buffer, 1, len, fin);
    fclose(fin);

    struct AES_ctx ctx;
    uint8_t key[32];
    derive_key(key);
    AES_init_ctx(&ctx, key);

    for (long i = 0; i < len; i += 16) {
        AES_ECB_decrypt(&ctx, buffer + i);
    }

    FILE *fout = fopen(output, "wb");
    fwrite(buffer, 1, len, fout);
    fclose(fout);
    free(buffer);
}

int main(void) {
    const char *encrypted = "game_encrypted.block";
    const char *decrypted = "game_decrypted.blend";

    decrypt_file(encrypted, decrypted);

    //execlp("blenderplayer", "blenderplayer", decrypted, NULL);
    return 0;
}

