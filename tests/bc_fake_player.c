/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Test stand-in for the UPBGE player. Follows the player side of the launcher contract
 * (binarycrypt_format.h): reads the hand-off from the pipe named by UPBGE_BC_KEY_PIPE up to end
 * of file, then checks that the main file it was given decrypts, with the key its header names, to
 * the file named by BC_TEST_EXPECTED (decompressed first when the export compressed it, as
 * Blender's reader does).
 *
 * Exit codes: 0 ok, 10 no key pipe, 11 key read failed, 12 decryption failed, 13 unexpected
 * arguments (the launcher must pass exactly one: the main file), 14 content mismatch, 15 a handle
 * planted by the test in the launcher's parent (BC_TEST_LEAK) reached the player. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

#include "bc_test_decrypt.h"

#include <zstd.h>

/** \return the number of keys of a well formed hand-off (header, keys, extension, then end of
 * file), 0 otherwise. One byte of room past the largest one detects trailing data. */
static int bc_read_keys(const char *value, uint8_t keys[BC_KEYS_MAX][BC_KEY_SIZE])
{
  static uint8_t data[BC_HANDOFF_HEADER_SIZE + BC_KEYS_MAX * BC_KEY_SIZE + BC_HANDOFF_EXTENSION_MAX + 1];
  const unsigned long long handle = strtoull(value, NULL, 10);
  const size_t capacity = sizeof(data);
  uint8_t *dst = data;
  size_t done = 0;
#ifdef _WIN32
  while (done < capacity) {
    DWORD n = 0;
    if (!ReadFile((HANDLE)(uintptr_t)handle, dst + done, (DWORD)(capacity - done), &n, NULL) || n == 0) {
      break;
    }
    done += n;
  }
#else
  while (done < capacity) {
    const ssize_t n = read((int)handle, dst + done, capacity - done);
    if (n <= 0) {
      break;
    }
    done += (size_t)n;
  }
#endif
  uint32_t extension_size = 0;
  const int count = done >= BC_HANDOFF_HEADER_SIZE ? bc_handoff_header_read(data, &extension_size) : 0;
  if (count == 0 || done != BC_HANDOFF_HEADER_SIZE + (size_t)count * BC_KEY_SIZE + extension_size) {
    return 0;
  }
  memcpy(keys, data + BC_HANDOFF_HEADER_SIZE, (size_t)count * BC_KEY_SIZE);
  return count;
}

/** True when the pipe named by BC_TEST_LEAK is open here and still holds the test's marker. */
static bool bc_leaked(void)
{
  const char *value = getenv("BC_TEST_LEAK");
  if (value == NULL) {
    return false;
  }
  const unsigned long long handle = strtoull(value, NULL, 10);
  char marker[6] = {0};
#ifdef _WIN32
  DWORD n = 0;
  if (!PeekNamedPipe((HANDLE)(uintptr_t)handle, marker, sizeof(marker), &n, NULL, NULL)) {
    return false;
  }
#else
  const int fd = (int)handle;
  if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
    return false;
  }
  const ssize_t n = read(fd, marker, sizeof(marker));
#endif
  return n == (int)sizeof(marker) && memcmp(marker, "LEAKED", sizeof(marker)) == 0;
}

int main(int argc, char **argv)
{
  /* Exactly what the launcher passes: -t <game name>, "-g <name> = 1" per debug display, then the
   * main file. Anything else fails: no argument of the launcher's own may reach the player. */
  if (argc < 4 || strcmp(argv[1], "-t") != 0 || (argc - 4) % 4 != 0) {
    fprintf(stderr, "fake player: expected -t <title> [-g <name> = 1]... <file>, got %d argument(s)\n", argc - 1);
    return 13;
  }
  char shown[256] = "";
  for (int i = 3; i + 1 < argc; i += 4) {
    if (strcmp(argv[i], "-g") != 0 || strcmp(argv[i + 2], "=") != 0 || strcmp(argv[i + 3], "1") != 0) {
      fprintf(stderr, "fake player: unexpected argument '%s'\n", argv[i]);
      return 13;
    }
    snprintf(shown + strlen(shown), sizeof(shown) - strlen(shown), " %s", argv[i + 1]);
  }
  const char *title = argv[2];
  const char *main_file = argv[argc - 1];
  const char *pipe_value = getenv(BC_KEY_PIPE_ENV);
  if (pipe_value == NULL) {
    return 10;
  }
  static uint8_t keys[BC_KEYS_MAX][BC_KEY_SIZE];
  const int key_count = bc_read_keys(pipe_value, keys);
  if (key_count == 0) {
    return 11;
  }
  uint8_t *plain = NULL, *expected = NULL;
  uint64_t plain_size = 0, expected_size = 0;
  bool decrypted = false;
  for (int i = 0; i < key_count && !decrypted; i++) {
    decrypted = bc_test_decrypt(main_file, keys[i], &plain, &plain_size); /* Checks the key id first. */
  }
  if (!decrypted) {
    fprintf(stderr, "fake player: cannot decrypt '%s'\n", main_file);
    return 12;
  }
  const char *expected_path = getenv("BC_TEST_EXPECTED");
  const bool loaded = expected_path != NULL &&
                      bc_test_read_file(expected_path, &expected, &expected_size);
  if (loaded && plain_size >= 4 && plain[0] == 0x28 && plain[1] == 0xb5 && plain[2] == 0x2f && plain[3] == 0xfd) {
    /* Every frame and the skippable seek table frame, in one call. */
    uint8_t *unpacked = (uint8_t *)malloc((size_t)expected_size + 1);
    const size_t n = unpacked ? ZSTD_decompress(unpacked, (size_t)expected_size + 1, plain, (size_t)plain_size) : 0;
    free(plain);
    plain = unpacked;
    plain_size = (unpacked != NULL && !ZSTD_isError(n)) ? n : 0;
  }
  const bool match = loaded && expected_size == plain_size &&
                     memcmp(expected, plain, (size_t)plain_size) == 0;
  free(plain);
  if (loaded) {
    free(expected);
  }
  if (!match) {
    fprintf(stderr, "fake player: decrypted content does not match\n");
    return 14;
  }
  if (bc_leaked()) {
    fprintf(stderr, "fake player: inherited a handle of the launcher's parent\n");
    return 15;
  }
  printf("fake player: '%s' decrypted correctly (%llu bytes, %d key(s)) in the window '%s', showing:%s\n",
         main_file,
         (unsigned long long)plain_size,
         key_count,
         title,
         shown[0] ? shown : " nothing");
  return 0;
}
