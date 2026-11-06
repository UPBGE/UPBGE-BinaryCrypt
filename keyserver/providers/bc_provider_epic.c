/* SPDX-License-Identifier: MIT */

/* Epic Games Store key provider: proves ownership with an EOS ownership token.
 *
 * The Epic Games launcher starts the game with -AUTH_TYPE=exchangecode -AUTH_PASSWORD=<code>; the
 * game executable forwards its arguments to the provider, which logs in with that exchange code,
 * asks EOS for an ownership token (a JWT signed by Epic, valid for minutes) for the catalog items
 * of the game, and sends it to the key server, which verifies the signature with Epic's public
 * keys (bc_keyserver.py, "epic" section).
 *
 * Configure at build time with your product's values from the Epic Developer Portal (CMake
 * cache variables BCP_EPIC_*, see CMakeLists.txt). Client credentials of a "GameClient" policy are
 * meant to ship inside games. Ship EOSSDK-Win64-Shipping.dll (or the Linux/macOS library) next to
 * the provider.
 *
 * Written against the EOS C SDK; not built in the UPBGE-BinaryCrypt CI because the SDK is not
 * redistributable. */

#ifndef _WIN32
#  define _POSIX_C_SOURCE 200809L /* nanosleep */
#endif

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  define bcp_sleep_ms(ms) Sleep(ms)
#else
#  include <time.h>
static void bcp_sleep_ms(const long ms)
{
  const struct timespec wait = {ms / 1000, (ms % 1000) * 1000000L};
  nanosleep(&wait, NULL);
}
#endif

#include "bc_provider.h"
#include "eos_sdk.h"
#include "eos_auth.h"
#include "eos_ecom.h"

#if !defined(BCP_EPIC_PRODUCT_ID) || !defined(BCP_EPIC_SANDBOX_ID) || !defined(BCP_EPIC_DEPLOYMENT_ID) || \
    !defined(BCP_EPIC_CLIENT_ID) || !defined(BCP_EPIC_CLIENT_SECRET) || !defined(BCP_EPIC_CATALOG_ITEM_ID)
#  error "Set BCP_EPIC_PRODUCT_ID, _SANDBOX_ID, _DEPLOYMENT_ID, _CLIENT_ID, _CLIENT_SECRET and _CATALOG_ITEM_ID"
#endif
#ifndef BCP_EPIC_KEY_URL
#  define BCP_EPIC_KEY_URL NULL
#endif

typedef struct BCP_EpicState {
  int pending;
  EOS_EResult result;
  EOS_EpicAccountId user;
  char token[16384];
} BCP_EpicState;

static void EOS_CALL bcp_on_login(const EOS_Auth_LoginCallbackInfo *data)
{
  BCP_EpicState *state = (BCP_EpicState *)data->ClientData;
  state->result = data->ResultCode;
  state->user = data->LocalUserId;
  state->pending = 0;
}

static void EOS_CALL bcp_on_token(const EOS_Ecom_QueryOwnershipTokenCallbackInfo *data)
{
  BCP_EpicState *state = (BCP_EpicState *)data->ClientData;
  state->result = data->ResultCode;
  if (data->ResultCode == EOS_Success && data->OwnershipToken != NULL) {
    snprintf(state->token, sizeof(state->token), "%s", data->OwnershipToken);
  }
  state->pending = 0;
}

/** Tick the platform until the callback cleared state->pending, at most 20 s. */
static void bcp_wait(EOS_HPlatform platform, BCP_EpicState *state)
{
  for (int i = 0; i < 2000 && state->pending; i++) {
    EOS_Platform_Tick(platform);
    bcp_sleep_ms(10);
  }
}

int main(int argc, char **argv)
{
  BCP_Request request;
  if (!bcp_parse_args(argc, argv, BCP_EPIC_KEY_URL, &request)) {
    return 1;
  }
  const char *exchange_code = bcp_find_arg(&request, "-AUTH_PASSWORD=");
  if (exchange_code == NULL) {
    return bcp_fail("start the game from the Epic Games launcher");
  }

  EOS_InitializeOptions init;
  memset(&init, 0, sizeof(init));
  init.ApiVersion = EOS_INITIALIZE_API_LATEST;
  init.ProductName = "UPBGE-BinaryCrypt provider";
  init.ProductVersion = "1.0";
  if (EOS_Initialize(&init) != EOS_Success) {
    return bcp_fail("cannot initialize Epic Online Services");
  }
  EOS_Platform_Options options;
  memset(&options, 0, sizeof(options));
  options.ApiVersion = EOS_PLATFORM_OPTIONS_API_LATEST;
  options.ProductId = BCP_EPIC_PRODUCT_ID;
  options.SandboxId = BCP_EPIC_SANDBOX_ID;
  options.DeploymentId = BCP_EPIC_DEPLOYMENT_ID;
  options.ClientCredentials.ClientId = BCP_EPIC_CLIENT_ID;
  options.ClientCredentials.ClientSecret = BCP_EPIC_CLIENT_SECRET;
  options.Flags = EOS_PF_DISABLE_OVERLAY; /* No window: the game comes next. */
  EOS_HPlatform platform = EOS_Platform_Create(&options);
  if (platform == NULL) {
    EOS_Shutdown();
    return bcp_fail("cannot initialize Epic Online Services");
  }

  static BCP_EpicState state;
  EOS_Auth_Credentials credentials;
  memset(&credentials, 0, sizeof(credentials));
  credentials.ApiVersion = EOS_AUTH_CREDENTIALS_API_LATEST;
  credentials.Type = EOS_LCT_ExchangeCode;
  credentials.Token = exchange_code;
  EOS_Auth_LoginOptions login;
  memset(&login, 0, sizeof(login));
  login.ApiVersion = EOS_AUTH_LOGIN_API_LATEST;
  login.Credentials = &credentials;
  login.ScopeFlags = EOS_AS_BasicProfile;
  state.pending = 1;
  EOS_Auth_Login(EOS_Platform_GetAuthInterface(platform), &login, &state, bcp_on_login);
  bcp_wait(platform, &state);

  if (!state.pending && state.result == EOS_Success) {
    const char *items[] = {BCP_EPIC_CATALOG_ITEM_ID};
    EOS_Ecom_QueryOwnershipTokenOptions query;
    memset(&query, 0, sizeof(query));
    query.ApiVersion = EOS_ECOM_QUERYOWNERSHIPTOKEN_API_LATEST;
    query.LocalUserId = state.user;
    query.CatalogItemIds = items;
    query.CatalogItemIdCount = 1;
    state.pending = 1;
    EOS_Ecom_QueryOwnershipToken(EOS_Platform_GetEcomInterface(platform), &query, &state, bcp_on_token);
    bcp_wait(platform, &state);
  }
  const int timed_out = state.pending;
  const EOS_EResult result = state.result;
  EOS_Platform_Release(platform);
  EOS_Shutdown();

  if (timed_out) {
    return bcp_fail("Epic Online Services did not answer: check the internet connection");
  }
  if (result != EOS_Success || state.token[0] == '\0') {
    return bcp_fail("Epic Online Services refused (%s)", EOS_EResult_ToString(result));
  }
  return bcp_exchange(&request, "epic", state.token);
}
