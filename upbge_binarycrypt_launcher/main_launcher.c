#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

#define SALT_LEN 16

static const char* password = ENCRYPTION_PASSWORD;
static const uint8_t salt[16] = {ENCRYPTION_SALT};

void derive_key(uint8_t* key_out) {
    for (int i = 0; i < 32; i++) {
        key_out[i] = (uint8_t)(password[i % strlen(password)] ^ salt[i % SALT_LEN]);
    }
}

static int decrypt_file(const char* input, const char* output) {
    FILE* fin = fopen(input, "rb");
    if (!fin) {
        fprintf(stderr, "Error opening input file '%s'\n", input);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long len = ftell(fin);
    rewind(fin);

    if (len <= 0) {
        fprintf(stderr, "Empty or invalid input file\n");
        fclose(fin);
        return 1;
    }

    // Adjust to 16-byte multiples for AES ECB
    if (len % 16 != 0) {
        fprintf(stderr, "File is not a multiple of 16 bytes, AES ECB requires multiples of 16\n");
        fclose(fin);
        return 1;
    }

    uint8_t* buffer = malloc(len);
    if (!buffer) {
        fprintf(stderr, "Error allocating memory\n");
        fclose(fin);
        return 1;
    }

    size_t read_bytes = fread(buffer, 1, len, fin);
    fclose(fin);
    if (read_bytes != len) {
        fprintf(stderr, "Error reading input file\n");
        free(buffer);
        return 1;
    }

    struct AES_ctx ctx;
    uint8_t key[32];
    derive_key(key);
    AES_init_ctx(&ctx, key);

    for (long i = 0; i < len; i += 16) {
        AES_ECB_decrypt(&ctx, buffer + i);
    }

    // Get padding value (last byte)
    uint8_t pad_val = buffer[len - 1];
    if (pad_val == 0 || pad_val > 16) {
        fprintf(stderr, "Error: invalid padding\n");
        free(buffer);
        return 1;
    }

    // Validate PKCS#7 padding
    for (long i = len - pad_val; i < len; i++) {
        if (buffer[i] != pad_val) {
            fprintf(stderr, "Error: corrupt padding\n");
            free(buffer);
            return 1;
        }
    }

    long output_len = len - pad_val;

    FILE* fout = fopen(output, "wb");
    if (!fout) {
        fprintf(stderr, "Error opening output file '%s'\n", output);
        free(buffer);
        return 1;
    }
    fwrite(buffer, 1, output_len, fout);
    fclose(fout);
    free(buffer);
    printf("Decrypted file successfully created: %s\n", output);
    return 0;
}

int launch_blenderplayer(const char *blend_file) {
    char cmd[512];

#if defined(_WIN32)
    snprintf(cmd, sizeof(cmd), "blenderplayer\\blenderplayer.exe \"%s\"", blend_file);
#else
    snprintf(cmd, sizeof(cmd), "./blenderplayer/blenderplayer \"%s\"", blend_file);
#endif

    printf("Executing: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Error running blenderplayer (code %d)\n", ret);
    }
    return ret;
}

int main(void) {
    const char* encrypted = "game_encrypted.block";
    const char* decrypted = "game_decrypted.blend";

    if (decrypt_file(encrypted, decrypted)) {
        fprintf(stderr, "Error decrypting file. blenderplayer will not be launched\n");
        return 1;
    }

    printf("Launching blenderplayer with file %s\n", decrypted);
    return launch_blenderplayer(decrypted);

    return 0;
}
