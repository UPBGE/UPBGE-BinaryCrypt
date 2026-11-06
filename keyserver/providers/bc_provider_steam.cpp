// SPDX-License-Identifier: MIT

/* Steam key provider: proves ownership with an Encrypted App Ticket.
 *
 * The ticket is encrypted by Steam with your app's "Encrypted App Ticket Key" (Steamworks: App
 * Admin, Security / SDK Auth). Only the key server holds that key; it decrypts the ticket and
 * checks that the Steam account owns the app (bc_keyserver.py, "steam" section).
 *
 * Ship next to the provider: steam_api64.dll (Windows), libsteam_api.so (Linux) or
 * libsteam_api.dylib (macOS) from the Steamworks SDK. While testing outside Steam, a
 * steam_appid.txt holding your app id must sit in the game folder (the provider's working
 * directory); never ship it.
 *
 * Written against the Steamworks SDK C++ API (steam_api.h); not built in the UPBGE-BinaryCrypt CI
 * because the SDK is not redistributable. */

#include <chrono>
#include <thread>

#include "bc_provider.h"
#include "steam/steam_api.h"

#ifndef BCP_STEAM_KEY_URL
#  define BCP_STEAM_KEY_URL NULL /* Or bake your key server in: -DBCP_STEAM_KEY_URL="\"https://...\"" */
#endif

namespace {

struct TicketRequest {
  bool done = false;
  EResult result = k_EResultFail;
  CCallResult<TicketRequest, EncryptedAppTicketResponse_t> call;

  void on_ticket(EncryptedAppTicketResponse_t *response, bool io_failure)
  {
    done = true;
    result = io_failure ? k_EResultIOFailure : response->m_eResult;
  }
};

}  // namespace

int main(int argc, char **argv)
{
  BCP_Request request;
  if (!bcp_parse_args(argc, argv, BCP_STEAM_KEY_URL, &request)) {
    return 1;
  }
  if (!SteamAPI_Init()) {
    return bcp_fail("Steam is not running, or this game is not in your Steam library: start the game from Steam");
  }

  TicketRequest ticket_request;
  ticket_request.call.Set(SteamUser()->RequestEncryptedAppTicket(nullptr, 0), &ticket_request, &TicketRequest::on_ticket);
  for (int i = 0; i < 1500 && !ticket_request.done; i++) { /* 15 s */
    SteamAPI_RunCallbacks();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  /* Steam allows one request per minute. A relaunch within that minute gets k_EResultLimitExceeded,
   * but the ticket from the previous request is still available and still valid. */
  uint8 ticket[4096];
  uint32 ticket_size = 0;
  const bool usable = ticket_request.done && (ticket_request.result == k_EResultOK || ticket_request.result == k_EResultLimitExceeded);
  const bool got = usable && SteamUser()->GetEncryptedAppTicket(ticket, sizeof(ticket), &ticket_size);
  SteamAPI_Shutdown();
  if (!got) {
    if (!ticket_request.done) {
      return bcp_fail("Steam did not answer: check that Steam is online");
    }
    return bcp_fail("Steam did not provide an ownership ticket (result %d)", (int)ticket_request.result);
  }

  static char hex[2 * sizeof(ticket) + 1];
  bcp_hex(ticket, ticket_size, hex);
  return bcp_exchange(&request, "steam", hex);
}
