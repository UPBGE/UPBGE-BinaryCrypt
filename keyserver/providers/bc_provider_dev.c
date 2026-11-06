/* SPDX-License-Identifier: MIT */

/* Development provider: proves nothing about ownership, it sends a shared token taken from the
 * BC_DEV_TOKEN environment variable. For testing the whole chain (launcher, provider, key server)
 * before a store is involved, and a starting point for a provider of your own (for example one
 * that sends a license key the player typed). Never enable dev tokens on a public key server. */

#include <stdlib.h>

#include "bc_provider.h"

int main(int argc, char **argv)
{
  BCP_Request request;
  if (!bcp_parse_args(argc, argv, NULL, &request)) {
    return 1;
  }
  const char *token = getenv("BC_DEV_TOKEN");
  if (token == NULL || token[0] == '\0') {
    return bcp_fail("BC_DEV_TOKEN is not set");
  }
  return bcp_exchange(&request, "dev", token);
}
