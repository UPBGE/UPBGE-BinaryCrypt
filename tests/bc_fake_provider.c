/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Stand-in key provider and key server in one, for the end to end test: seals the requested keys,
 * found in the key file BC_TEST_PROVIDER_KEY_FILE, for the public key the launcher passed.
 *
 *   BC_TEST_PROVIDER_MODE        ok (default) | noise | fail | silent | garbage
 *   BC_TEST_PROVIDER_EXPECT_ARG  an argument the launcher must have forwarded
 *   BC_TEST_PROVIDER_EXPECT_URL  the key server URL the launcher must have passed
 *   BC_TEST_PROVIDER_LOG         file that receives the requested key ids, one line per run */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc_envelope.h"
#include "bc_key.h"
#include "bc_keyring.h"
#include "bc_platform.h"

static bool from_hex(const char *text, uint8_t *out, size_t n)
{
  if (strlen(text) != 2 * n) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    unsigned int v;
    if (sscanf(text + 2 * i, "%2x", &v) != 1) {
      return false;
    }
    out[i] = (uint8_t)v;
  }
  return true;
}

int main(int argc, char **argv)
{
  if (argc < 4) {
    printf("BCERROR the test provider needs <url> <key id> <public key>\n");
    return 2;
  }
  const char *mode = getenv("BC_TEST_PROVIDER_MODE");
  const char *expect_arg = getenv("BC_TEST_PROVIDER_EXPECT_ARG");
  const char *expect_url = getenv("BC_TEST_PROVIDER_EXPECT_URL");
  mode = (mode && *mode) ? mode : "ok";
  if (expect_url && *expect_url && strcmp(argv[1], expect_url) != 0) {
    printf("BCERROR unexpected key server URL '%s'\n", argv[1]);
    return 1;
  }
  if (expect_arg && *expect_arg) {
    bool found = false;
    for (int i = 4; i < argc; i++) {
      found = found || strcmp(argv[i], expect_arg) == 0;
    }
    if (!found) {
      printf("BCERROR the argument '%s' was not forwarded\n", expect_arg);
      return 1;
    }
  }
  if (strcmp(mode, "fail") == 0) {
    printf("store SDK: some log line\nBCERROR test provider refused\nstore SDK: shutdown\n");
    return 1;
  }
  if (strcmp(mode, "silent") == 0) {
    fprintf(stderr, "Store API init failed\n");
    return 3;
  }

  const char *key_file = getenv("BC_TEST_PROVIDER_KEY_FILE");
  const char *log_file = getenv("BC_TEST_PROVIDER_LOG");
  BC_KeyRing ring;
  char err[512];
  uint8_t client_public[BC_X25519_SIZE];
  bc_keyring_init(&ring);
  if (key_file == NULL || !bc_keyring_load(&ring, key_file, err, sizeof(err)) ||
      !from_hex(argv[3], client_public, BC_X25519_SIZE))
  {
    printf("BCERROR the test provider cannot read its inputs\n");
    return 1;
  }
  if (log_file != NULL && *log_file) {
    FILE *log = bc_fopen(log_file, "ab");
    if (log != NULL) {
      fprintf(log, "%s\n", argv[2]);
      fclose(log);
    }
  }
  if (strcmp(mode, "noise") == 0) {
    printf("[S_API] SteamAPI_Init(): Loaded local 'steamclient.so' OK.\n");
  }
  /* "id,id,...": one envelope per id, same order. The "wrong" key of the test is the newest key
   * whatever was asked (a misconfigured server). */
  char ids[BC_KEYS_MAX * 17 + 1];
  snprintf(ids, sizeof(ids), "%s", argv[2]);
  for (char *id = strtok(ids, ","); id != NULL; id = strtok(NULL, ",")) {
    uint8_t key_id[BC_KEY_ID_SIZE], envelope[BC_ENVELOPE_SIZE];
    const int index = from_hex(id, key_id, BC_KEY_ID_SIZE) ? bc_keyring_find_id(&ring, key_id) : -1;
    const int sealed = strcmp(mode, "wrongkey") == 0 ? ring.key_count - 1 : index;
    if (index < 0 && strcmp(mode, "wrongkey") != 0) {
      printf("BCERROR unknown key id %s\n", id);
      return 1;
    }
    if (strcmp(mode, "garbage") == 0) {
      memset(envelope, 0x5A, sizeof(envelope));
    }
    else if (!bc_envelope_seal(ring.keys[sealed], key_id, client_public, envelope)) {
      printf("BCERROR cannot seal\n");
      return 1;
    }
    printf("BCENVELOPE ");
    for (int i = 0; i < BC_ENVELOPE_SIZE; i++) {
      printf("%02x", envelope[i]);
    }
    printf("\n");
  }
  bc_keyring_free(&ring);
  return 0;
}
