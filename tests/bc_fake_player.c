/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Test stand-in for the UPBGE player. Follows the player side of the launcher contract
 * (binarycrypt_format.h): reads the keys from the pipe named by UPBGE_BC_KEY_PIPE up to end of
 * file, then checks that the main file it was given decrypts, with the key its header names, to
 * the file named by BC_TEST_EXPECTED.
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

/** \return the number of whole keys read, 0 on a malformed hand-off. */
static int bc_read_keys(const char *value, uint8_t keys[BC_KEYS_MAX][BC_KEY_SIZE])
{
  const unsigned long long handle = strtoull(value, NULL, 10);
  const size_t capacity = (size_t)BC_KEYS_MAX * BC_KEY_SIZE;
  uint8_t *dst = &keys[0][0];
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
  return done % BC_KEY_SIZE == 0 ? (int)(done / BC_KEY_SIZE) : 0;
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
  if (argc != 2) {
    fprintf(stderr, "fake player: expected exactly one argument, got %d\n", argc - 1);
    return 13;
  }
  const char *pipe_value = getenv(BC_KEY_PIPE_ENV);
  if (pipe_value == NULL) {
    return 10;
  }
  static uint8_t keys[BC_KEYS_MAX][BC_KEY_SIZE];
  const int key_count = bc_read_keys(pipe_value, keys);
  if (key_count == 0) {
    return 11;
  }
  uint8_t *plain = NULL, *expected;
  uint64_t plain_size, expected_size;
  bool decrypted = false;
  for (int i = 0; i < key_count && !decrypted; i++) {
    decrypted = bc_test_decrypt(argv[1], keys[i], &plain, &plain_size); /* Checks the key id first. */
  }
  if (!decrypted) {
    fprintf(stderr, "fake player: cannot decrypt '%s'\n", argv[1]);
    return 12;
  }
  const char *expected_path = getenv("BC_TEST_EXPECTED");
  const bool loaded = expected_path != NULL &&
                      bc_test_read_file(expected_path, &expected, &expected_size);
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
  printf("fake player: '%s' decrypted correctly (%llu bytes, %d key(s))\n",
         argv[1],
         (unsigned long long)plain_size,
         key_count);
  return 0;
}
