/* SPDX-License-Identifier: MIT */

/* Meta (Meta Horizon Store, PC VR) key provider: proves ownership with a Meta user proof.
 *
 * The provider initializes the Meta Platform SDK for the game's app id, checks the entitlement
 * locally (a quick, clear refusal for a player who does not own the game), then sends the logged
 * in user's id and a one-use nonce (user proof) to the key server. The server checks both with
 * Meta: the nonce proves who the player is (user_nonce_validate), the entitlement check that this
 * account owns the app (verify_entitlement), with the app secret only the server knows
 * (bc_keyserver.py, "meta" section).
 *
 * Windows only (the Meta Horizon Store sells PC VR games for Windows). Configure at build time
 * with BCP_META_APP_ID (CMakeLists.txt). Nothing ships next to the provider: the Meta app installed
 * on the player's computer brings the platform library, which the SDK's loader finds.
 *
 * Written against the Meta Platform SDK C API (OVR_Platform.h); not built in the UPBGE-BinaryCrypt
 * CI because the SDK is not redistributable. */

#include <stdio.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "OVR_Platform.h"
#include "bc_provider.h"

#ifndef BCP_META_APP_ID
#  error "Set BCP_META_APP_ID to the app id from the Meta Horizon developer dashboard"
#endif
#ifndef BCP_META_KEY_URL
#  define BCP_META_KEY_URL NULL /* Or bake your key server in: -DBCP_META_KEY_URL="\"https://...\"" */
#endif

/** The answer to a request: messages are queued, first in first out. Others are dropped. NULL after
 * 20 s (the platform service does not answer). */
static ovrMessageHandle bcp_wait_for(const ovrMessageType type)
{
  for (int i = 0; i < 2000; i++) {
    ovrMessageHandle message;
    while ((message = ovr_PopMessage()) != NULL) {
      if (ovr_Message_GetType(message) == type) {
        return message;
      }
      ovr_FreeMessage(message);
    }
    Sleep(10);
  }
  return NULL;
}

int main(int argc, char **argv)
{
  BCP_Request request;
  if (!bcp_parse_args(argc, argv, BCP_META_KEY_URL, &request)) {
    return 1;
  }
  if (ovr_PlatformInitializeWindows(BCP_META_APP_ID) != ovrPlatformInitialize_Success) {
    return bcp_fail("cannot reach the Meta Quest Link app: start it, sign in, then start the game again");
  }

  ovr_Entitlement_GetIsViewerEntitled();
  ovrMessageHandle message = bcp_wait_for(ovrMessage_Entitlement_GetIsViewerEntitled);
  if (message == NULL) {
    return bcp_fail("the Meta platform did not answer: start the game again");
  }
  const bool entitled = !ovr_Message_IsError(message);
  ovr_FreeMessage(message);
  if (!entitled) {
    return bcp_fail("this Meta account does not own the game");
  }

  ovr_User_GetLoggedInUser();
  message = bcp_wait_for(ovrMessage_User_GetLoggedInUser);
  if (message == NULL || ovr_Message_IsError(message)) {
    if (message != NULL) {
      ovr_FreeMessage(message);
    }
    return bcp_fail("no Meta account is signed in");
  }
  const ovrID user = ovr_User_GetID(ovr_Message_GetUser(message));
  ovr_FreeMessage(message);

  /* The nonce is good for one check only: the server spends it. */
  ovr_User_GetUserProof();
  message = bcp_wait_for(ovrMessage_User_GetUserProof);
  if (message == NULL || ovr_Message_IsError(message)) {
    if (message != NULL) {
      ovr_FreeMessage(message);
    }
    return bcp_fail("the Meta platform gave no user proof: start the game again");
  }
  char ticket[2048];
  const int n = snprintf(ticket, sizeof(ticket), "%llu:%s", (unsigned long long)user, ovr_UserProof_GetNonce(ovr_Message_GetUserProof(message)));
  ovr_FreeMessage(message);
  if (n < 0 || (size_t)n >= sizeof(ticket)) {
    return bcp_fail("the Meta user proof is too long");
  }
  return bcp_exchange(&request, "meta", ticket);
}
