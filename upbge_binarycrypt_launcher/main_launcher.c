#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

#define SALT_LEN 16

static const char *PASSWORD_STR = ENCRYPTION_PASSWORD;
static const uint8_t salt[16] = {ENCRYPTION_SALT};

void derive_key(uint8_t *key_out) {
    for (int i = 0; i < 32; i++) {
        key_out[i] = (uint8_t)(PASSWORD_STR[i % strlen(PASSWORD_STR)] ^ salt[i % SALT_LEN]);
    }
}

static int decrypt_file(const char *input, const char *output) {
    FILE *fin = fopen(input, "rb");
    if (!fin) {
        fprintf(stderr, "Error opening input file '%s'\n", input);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long len = ftell(fin);
    rewind(fin);

    if (len <= 0) {
        fprintf(stderr, "Archivo de entrada vacío o inválido\n");
        fclose(fin);
        return 1;
    }

    // Ajustar para múltiplos de 16 para AES ECB
    if (len % 16 != 0) {
        fprintf(stderr, "El archivo no es múltiplo de 16 bytes, AES ECB requiere múltiplos de 16\n");
        fclose(fin);
        return 1;
    }

    uint8_t *buffer = malloc(len);
    if (!buffer) {
        fprintf(stderr, "Error asignando memoria\n");
        fclose(fin);
        return 1;
    }

    size_t read_bytes = fread(buffer, 1, len, fin);
    fclose(fin);
    if (read_bytes != len) {
        fprintf(stderr, "Error leyendo archivo de entrada\n");
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

    // Obtener valor de padding (último byte)
    uint8_t pad_val = buffer[len - 1];
    if (pad_val == 0 || pad_val > 16) {
        fprintf(stderr, "Error: padding inválido\n");
        free(buffer);
        return 1;
    }

    // Validar padding PKCS#7
    for (long i = len - pad_val; i < len; i++) {
        if (buffer[i] != pad_val) {
            fprintf(stderr, "Error: padding corrupto\n");
            free(buffer);
            return 1;
        }
    }

    long output_len = len - pad_val;

    FILE *fout = fopen(output, "wb");
    if (!fout) {
        fprintf(stderr, "Error al abrir archivo de salida '%s'\n", output);
        free(buffer);
        return 1;
    }
    fwrite(buffer, 1, output_len, fout);
    fclose(fout);
    free(buffer);
    printf("Archivo desencriptado creado correctamente: %s\n", output);
    return 0;
}

int launch_blenderplayer(const char *blend_file) {
    char cmd[512];

#if defined(_WIN32)
    snprintf(cmd, sizeof(cmd), "blenderplayer\\blenderplayer.exe \"%s\"", blend_file);
#else
    snprintf(cmd, sizeof(cmd), "./blenderplayer/blenderplayer \"%s\"", blend_file);
#endif

    printf("Ejecutando: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Error ejecutando blenderplayer (code %d)\n", ret);
    }
    return ret;
}

int main(void) {
    const char *encrypted = "game_encrypted.block";
    const char *decrypted = "game_decrypted.blend";

    if (decrypt_file(encrypted, decrypted)) {
        fprintf(stderr, "Error encriptando el archivo. No se lanza el blenderplayer\n");
        return 1;
    }

    printf("Ejecutando blenderplayer con archivo %s\n", decrypted);
    return launch_blenderplayer(decrypted);

    return 0;
}

