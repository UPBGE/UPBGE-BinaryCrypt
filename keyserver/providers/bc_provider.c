/* SPDX-License-Identifier: MIT */

#include "bc_provider.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winhttp.h>
#else
#  include <curl/curl.h>
#endif

#define BCP_RESPONSE_MAX 65536
#define BCP_TIMEOUT_MS 30000

int bcp_fail(const char *format, ...)
{
  char message[1024];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  /* One line: the launcher reads lines. */
  for (char *c = message; *c; c++) {
    *c = (*c == '\n' || *c == '\r') ? ' ' : *c;
  }
  printf("BCERROR %s\n", message);
  fflush(stdout);
  return 1;
}

void bcp_hex(const uint8_t *data, const size_t size, char *out)
{
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < size; i++) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 15];
  }
  out[2 * size] = '\0';
}

static bool bcp_is_hex_digit(const char c)
{
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static bool bcp_is_hex(const char *s, const size_t digits)
{
  if (strlen(s) != digits) {
    return false;
  }
  for (; *s; s++) {
    if (!bcp_is_hex_digit(*s)) {
      return false;
    }
  }
  return true;
}

/** "id,id,...": 16 hex digits each, at most 64. */
static bool bcp_is_key_id_list(const char *s)
{
  int count = 0;
  for (;;) {
    for (int i = 0; i < 16; i++) {
      if (!bcp_is_hex_digit(s[i])) {
        return false;
      }
    }
    s += 16;
    count++;
    if (*s == '\0') {
      return count <= 64;
    }
    if (*s++ != ',') {
      return false;
    }
  }
}

bool bcp_parse_args(int argc, char **argv, const char *default_url, BCP_Request *r)
{
  memset(r, 0, sizeof(*r));
  if (argc < 4 || !bcp_is_key_id_list(argv[2]) || !bcp_is_hex(argv[3], 64)) {
    bcp_fail("this program is started by the game, not directly");
    return false;
  }
  r->url = strcmp(argv[1], "-") != 0 ? argv[1] : default_url;
  if (r->url == NULL || r->url[0] == '\0') {
    bcp_fail("no key server is configured for this game");
    return false;
  }
  r->key_ids = argv[2];
  r->client_public = argv[3];
  r->argc = argc - 4;
  r->argv = argv + 4;
  return true;
}

const char *bcp_find_arg(const BCP_Request *request, const char *prefix)
{
  const size_t n = strlen(prefix);
  for (int i = 0; i < request->argc; i++) {
    if (strncmp(request->argv[i], prefix, n) == 0) {
      return request->argv[i] + n;
    }
  }
  return NULL;
}

/* -------------------------------------------------------------------------------------------- */
/* JSON: just enough for this protocol. */

/** Append \a s as a JSON string. False when \a out is full. */
static bool bcp_json_string(char *out, const size_t size, size_t *len, const char *s)
{
  if (*len + 2 >= size) {
    return false;
  }
  out[(*len)++] = '"';
  for (; *s; s++) {
    char escaped[8];
    const unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      snprintf(escaped, sizeof(escaped), "\\%c", c);
    }
    else if (c < 32) {
      snprintf(escaped, sizeof(escaped), "\\u%04x", c);
    }
    else {
      escaped[0] = (char)c;
      escaped[1] = '\0';
    }
    const size_t n = strlen(escaped);
    if (*len + n + 2 >= size) {
      return false;
    }
    memcpy(out + *len, escaped, n);
    *len += n;
  }
  out[(*len)++] = '"';
  out[*len] = '\0';
  return true;
}

/** Print one "BCENVELOPE" line per string of the array member \a name (hex only, no escapes).
 * \return the number printed. */
static int bcp_print_envelopes(const char *json, const char *name)
{
  char pattern[64];
  snprintf(pattern, sizeof(pattern), "\"%s\"", name);
  const char *p = strstr(json, pattern);
  if (p == NULL) {
    return 0;
  }
  p += strlen(pattern);
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') {
    p++;
  }
  if (*p++ != '[') {
    return 0;
  }
  int count = 0;
  for (;;) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') {
      p++;
    }
    if (*p != '"') {
      break;
    }
    const char *end = strchr(++p, '"');
    if (end == NULL || end - p != 160) {
      break;
    }
    printf("BCENVELOPE %.160s\n", p);
    count++;
    p = end + 1;
  }
  fflush(stdout);
  return count;
}

/** Value of the string member \a name, unescaped (\" \\ \n only) into \a out. */
static bool bcp_json_get(const char *json, const char *name, char *out, const size_t size)
{
  char pattern[64];
  snprintf(pattern, sizeof(pattern), "\"%s\"", name);
  const char *p = strstr(json, pattern);
  if (p == NULL) {
    return false;
  }
  p += strlen(pattern);
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') {
    p++;
  }
  if (*p++ != '"') {
    return false;
  }
  size_t n = 0;
  for (; *p && *p != '"' && n + 1 < size; p++) {
    if (*p == '\\' && p[1] != '\0') {
      p++;
      out[n++] = *p == 'n' ? ' ' : *p;
    }
    else {
      out[n++] = *p;
    }
  }
  out[n] = '\0';
  return *p == '"';
}

/* -------------------------------------------------------------------------------------------- */
/* HTTPS POST: WinHTTP on Windows, libcurl elsewhere. Certificates are always verified. */

typedef struct BCP_Response {
  char *data;
  size_t size;
  long status;
} BCP_Response;

#ifdef _WIN32

static bool bcp_post(const char *url, const char *body, BCP_Response *response, char *err, const size_t err_size)
{
  wchar_t wurl[2048], host[256], path[2048], extra[2048];
  if (MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 2048) == 0) {
    snprintf(err, err_size, "invalid key server URL");
    return false;
  }
  URL_COMPONENTS uc;
  memset(&uc, 0, sizeof(uc));
  uc.dwStructSize = sizeof(uc);
  uc.lpszHostName = host;
  uc.dwHostNameLength = 256;
  uc.lpszUrlPath = path;
  uc.dwUrlPathLength = 2048;
  uc.lpszExtraInfo = extra;
  uc.dwExtraInfoLength = 2048;
  if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
    snprintf(err, err_size, "invalid key server URL");
    return false;
  }
  wchar_t object[4096];
  _snwprintf(object, 4096, L"%ls%ls", path[0] ? path : L"/", extra);
  object[4095] = L'\0';

  bool ok = false;
  HINTERNET session = WinHttpOpen(L"UPBGE-BinaryCrypt-provider/1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  HINTERNET connection = session ? WinHttpConnect(session, host, uc.nPort, 0) : NULL;
  HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST", object, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0) : NULL;
  if (session != NULL) {
    WinHttpSetTimeouts(session, BCP_TIMEOUT_MS, BCP_TIMEOUT_MS, BCP_TIMEOUT_MS, BCP_TIMEOUT_MS);
  }
  const DWORD body_size = (DWORD)strlen(body);
  if (request != NULL &&
      WinHttpSendRequest(request, L"Content-Type: application/json\r\n", (DWORD)-1L, (void *)body, body_size, body_size, 0) &&
      WinHttpReceiveResponse(request, NULL))
  {
    DWORD status = 0, status_size = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX);
    response->status = (long)status;
    ok = true;
    for (;;) {
      char buffer[4096];
      DWORD read = 0;
      if (!WinHttpReadData(request, buffer, sizeof(buffer), &read) || read == 0) {
        break;
      }
      const size_t keep = response->size + read < BCP_RESPONSE_MAX ? read : BCP_RESPONSE_MAX - 1 - response->size;
      memcpy(response->data + response->size, buffer, keep);
      response->size += keep;
    }
    response->data[response->size] = '\0';
  }
  else {
    snprintf(err, err_size, "cannot reach the key server (error %lu): check the internet connection", GetLastError());
  }
  if (request) {
    WinHttpCloseHandle(request);
  }
  if (connection) {
    WinHttpCloseHandle(connection);
  }
  if (session) {
    WinHttpCloseHandle(session);
  }
  return ok;
}

#else

static size_t bcp_curl_write(char *ptr, size_t size, size_t count, void *user)
{
  BCP_Response *response = (BCP_Response *)user;
  const size_t n = size * count;
  const size_t keep = response->size + n < BCP_RESPONSE_MAX ? n : BCP_RESPONSE_MAX - 1 - response->size;
  memcpy(response->data + response->size, ptr, keep);
  response->size += keep;
  response->data[response->size] = '\0';
  return n;
}

static bool bcp_post(const char *url, const char *body, BCP_Response *response, char *err, const size_t err_size)
{
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    snprintf(err, err_size, "cannot initialize the HTTP client");
    return false;
  }
  struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "UPBGE-BinaryCrypt-provider/1");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)BCP_TIMEOUT_MS);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bcp_curl_write);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
  const CURLcode result = curl_easy_perform(curl);
  if (result == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status);
  }
  else {
    snprintf(err, err_size, "cannot reach the key server (%s): check the internet connection", curl_easy_strerror(result));
  }
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result == CURLE_OK;
}

#endif

int bcp_exchange(const BCP_Request *request, const char *platform, const char *ticket)
{
  const size_t body_size = strlen(ticket) * 6 + strlen(request->key_ids) * 2 + 512;
  char *body = (char *)malloc(body_size);
  BCP_Response response = {(char *)malloc(BCP_RESPONSE_MAX), 0, 0};
  if (body == NULL || response.data == NULL) {
    free(body);
    free(response.data);
    return bcp_fail("out of memory");
  }
  response.data[0] = '\0';
  size_t len = 0;
  bool ok = true;
  const char *names[3] = {"platform", "ticket", "client_public"};
  const char *values[3] = {platform, ticket, request->client_public};
  body[len++] = '{';
  for (int i = 0; i < 3 && ok; i++) {
    len += (size_t)snprintf(body + len, body_size - len, "%s\"%s\":", i ? "," : "", names[i]);
    ok = bcp_json_string(body, body_size, &len, values[i]);
  }
  /* "key_ids": the comma separated list as a JSON array (validated hex: no escaping needed). */
  ok = ok && len + strlen(request->key_ids) * 2 + 32 < body_size;
  if (ok) {
    len += (size_t)snprintf(body + len, body_size - len, ",\"key_ids\":[\"");
    for (const char *c = request->key_ids; *c; c++) {
      if (*c == ',') {
        len += (size_t)snprintf(body + len, body_size - len, "\",\"");
      }
      else {
        body[len++] = *c;
      }
    }
    len += (size_t)snprintf(body + len, body_size - len, "\"]}");
  }

  char err[512] = "invalid request";
  char message[512];
  int exit_code;
  if (!ok || !bcp_post(request->url, body, &response, err, sizeof(err))) {
    exit_code = bcp_fail("%s", err);
  }
  else if (response.status == 200 && bcp_print_envelopes(response.data, "envelopes") > 0) {
    exit_code = 0;
  }
  else if (bcp_json_get(response.data, "error", message, sizeof(message))) {
    exit_code = bcp_fail("%s", message);
  }
  else {
    exit_code = bcp_fail("the key server failed (HTTP %ld)", response.status);
  }
  free(body);
  free(response.data);
  return exit_code;
}
