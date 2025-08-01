#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <raylib.h>
#include "aes.h"

#define SALT_LEN 16
#define PASSWORD_STR ENCRYPTION_PASSWORD
static const uint8_t salt[] = {ENCRYPTION_SALT};

static void derive_key(uint8_t *key_out) {
    for (int i = 0; i < 32; i++) {
        key_out[i] = (uint8_t)(PASSWORD_STR[i % strlen(PASSWORD_STR)] ^ salt[i % SALT_LEN]);
    }
}

static void encrypt_file(const char *input, const char *output) {
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
        AES_ECB_encrypt(&ctx, buffer + i);
    }

    FILE *fout = fopen(output, "wb");
    fwrite(buffer, 1, len, fout);
    fclose(fout);
    free(buffer);
}

int main(void) {
    const int screenWidth = 600;
    const int screenHeight = 200;
    InitWindow(screenWidth, screenHeight, "UPBGE BinaryCrypt - Encryption Tool");

    const char *inputFile = "game.blend";
    const char *outputFile = "game_encrypted.block";

    Rectangle button = { screenWidth/2 - 100, screenHeight/2 - 25, 200, 50 };

    SetTargetFPS(60);
    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        DrawText("Click to encrypt 'game.blend'", 150, 40, 20, DARKGRAY);
        if (CheckCollisionPointRec(GetMousePosition(), button)) {
            DrawRectangleRec(button, LIGHTGRAY);
            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                encrypt_file(inputFile, outputFile);
            }
        } else {
            DrawRectangleRec(button, GRAY);
        }
        DrawText("Encrypt", button.x + 60, button.y + 15, 20, BLACK);

        EndDrawing();
    }

    CloseWindow();
    return 0;
}

