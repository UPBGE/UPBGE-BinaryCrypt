#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <raylib.h>
#include "aes.h"

#define SALT_LEN 16

static const char* password = ENCRYPTION_PASSWORD;
static const uint8_t salt[16] = {ENCRYPTION_SALT};

static void derive_key(uint8_t* key_out) {
    for (int i = 0; i < 32; i++) {
        key_out[i] = (uint8_t)(password[i % strlen(password)] ^ salt[i % SALT_LEN]);
    }
}

static void encrypt_file(const char* input, const char* output) {
    // Validate input parameters
    if (!input || !output) return;

    // Open input file
    FILE* fin = fopen(input, "rb");
    if (!fin) return;

    // Get file size with error checking
    if (fseek(fin, 0, SEEK_END)) {
        fclose(fin);
        return;
    }

    long len = ftell(fin);
    rewind(fin);

    // Validate file length (must be positive)
    if (len <= 0) {
        fclose(fin);
        return;
    }

    // Allocate buffer for file content
    uint8_t* buffer = malloc((size_t)len);
    if (!buffer) {
        fclose(fin);
        return;
    }

    // Read entire file with complete verification
    size_t bytes_read = fread(buffer, 1, (size_t)len, fin);
    fclose(fin);
    if (bytes_read != (size_t)len) {
        free(buffer);
        return;
    }

    // Calculate PKCS#7 padding
    int padding = 16 - (len % 16);
    if (padding == 0) padding = 16;  // Always add full block when aligned

    // Check for potential integer overflow
    if (len > LONG_MAX - padding) {
        free(buffer);
        return;
    }
    long padded_len = len + padding;

    // Allocate and prepare padded buffer
    uint8_t* buffer_padded = malloc((size_t)padded_len);
    if (!buffer_padded) {
        free(buffer);
        return;
    }

    // Copy original data and apply padding
    memcpy(buffer_padded, buffer, (size_t)len);
    memset(buffer_padded + len, (uint8_t)padding, (size_t)padding);

    // Initialize AES context
    struct AES_ctx ctx;
    uint8_t key[32];
    derive_key(key);
    AES_init_ctx(&ctx, key);

    // Encrypt each 16-byte block
    for (long i = 0; i < padded_len; i += 16) {
        AES_ECB_encrypt(&ctx, buffer_padded + i);
    }

    // Write encrypted data to output file
    FILE* fout = fopen(output, "wb");
    if (fout) {
        fwrite(buffer_padded, 1, (size_t)padded_len, fout);
        fclose(fout);
    }

    // Clean up allocated memory
    free(buffer);
    free(buffer_padded);
}


int main(void) {
    const int screenWidth = 600;
    const int screenHeight = 200;
    InitWindow(screenWidth, screenHeight, "UPBGE BinaryCrypt - Encryption Tool");

    const char* inputFile = "game.blend";
    const char* outputFile = "game_encrypted.block";

    Rectangle button = { (float)(screenWidth / 2 - 100), (float)(screenHeight / 2 - 25), 200.0f, 50.0f };

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
        DrawText("Encrypt", (int)button.x + 60, (int)button.y + 15, 20, BLACK);

        EndDrawing();
    }

    CloseWindow();
    return 0;
}

