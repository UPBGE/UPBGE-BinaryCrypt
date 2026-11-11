/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_online.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc_envelope.h"
#include "bc_key.h"
#include "bc_platform.h"
#include "blake3.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <shellapi.h>
#  include <wincrypt.h>
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <signal.h>
#  include <sys/stat.h>
#  include <sys/wait.h>
#  include <time.h>
#  include <unistd.h>
#  ifdef __APPLE__
#    include <uuid/uuid.h>
#  endif
#endif

#define BC_CACHE_CONTEXT "UPBGE-BinaryCrypt key cache v1"
#define BC_CACHE_FILE_MAX 4096

static void bc_to_hex(const uint8_t *data, const size_t n, char *out)
{
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 15];
  }
  out[2 * n] = '\0';
}

/** Exactly 2 * n hex digits. */
static bool bc_from_hex(const char *text, uint8_t *out, const size_t n)
{
  for (size_t i = 0; i < 2 * n; i++) {
    const char c = text[i];
    const int v = (c >= '0' && c <= '9') ? c - '0' :
                  (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                  (c >= 'A' && c <= 'F') ? c - 'A' + 10 :
                                           -1;
    if (v < 0) {
      return false;
    }
    out[i / 2] = (uint8_t)((i & 1) ? (out[i / 2] | v) : (v << 4));
  }
  return text[2 * n] == '\0';
}

/* -------------------------------------------------------------------------------------------- */
/* Provider process: runs with the game folder as working directory, its standard output and
 * error captured together, killed after BC_PROVIDER_TIMEOUT seconds. */

typedef struct BC_ProviderRun {
  char *out; /* NUL terminated, at most BC_PROVIDER_OUTPUT_MAX - 1 bytes kept */
  size_t used;
  int exit_code;
  bool timed_out;
} BC_ProviderRun;

static void bc_keep_output(BC_ProviderRun *run, const char *data, const size_t n)
{
  const size_t room = BC_PROVIDER_OUTPUT_MAX - 1 - run->used;
  const size_t keep = n < room ? n : room;
  memcpy(run->out + run->used, data, keep);
  run->used += keep;
  run->out[run->used] = '\0';
}

#ifdef _WIN32

bool bc_append_quoted(wchar_t *cmd, size_t size, size_t *len, const wchar_t *arg);
BOOL bc_create_process(const wchar_t *app,
                       wchar_t *cmd,
                       DWORD flags,
                       const wchar_t *dir,
                       const STARTUPINFOW *si,
                       const HANDLE *handles,
                       int count,
                       PROCESS_INFORMATION *pi);

static bool bc_run_provider(const char *provider,
                            const char *work_dir,
                            const char *const *args,
                            const int arg_count,
                            BC_ProviderRun *run)
{
  static wchar_t cmd[32768];
  size_t len = 0;
  bool ok = true;
  wchar_t *wprovider = bc_utf16(provider);
  wchar_t *wdir = bc_utf16(work_dir);
  if (wprovider == NULL || wdir == NULL) {
    free(wprovider);
    free(wdir);
    return false;
  }
  for (wchar_t *c = wprovider; *c; c++) {
    *c = *c == L'/' ? L'\\' : *c;
  }
  for (wchar_t *c = wdir; *c; c++) {
    *c = *c == L'/' ? L'\\' : *c;
  }
  ok = bc_append_quoted(cmd, 32768, &len, wprovider);
  for (int i = 0; ok && i < arg_count; i++) {
    wchar_t *w = bc_utf16(args[i]);
    ok = w != NULL && bc_append_quoted(cmd, 32768, &len, w);
    free(w);
  }
  /* The game executable's own arguments, in their original UTF-16 form. */
  int wargc = 0;
  wchar_t **wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
  for (int i = 1; ok && wargv != NULL && i < wargc; i++) {
    ok = bc_append_quoted(cmd, 32768, &len, wargv[i]);
  }
  if (wargv != NULL) {
    LocalFree(wargv);
  }

  HANDLE read_end = NULL, write_end = NULL, null_in = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  PROCESS_INFORMATION pi = {0};
  ok = ok && CreatePipe(&read_end, &write_end, &sa, 0) &&
       SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
  if (ok) {
    null_in = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = null_in;
    si.hStdOutput = write_end;
    si.hStdError = write_end;
    /* No console window: the provider is plumbing, the game window comes next. It inherits its
     * two standard handles and nothing else. */
    const HANDLE inherited[2] = {null_in, write_end};
    ok = bc_create_process(wprovider, cmd, CREATE_NO_WINDOW, wdir, &si, inherited, 2, &pi);
  }
  if (write_end != NULL) {
    CloseHandle(write_end); /* Only the provider holds it now: EOF when it exits. */
  }
  if (null_in != INVALID_HANDLE_VALUE) {
    CloseHandle(null_in);
  }
  free(wprovider);
  free(wdir);
  if (!ok) {
    if (read_end != NULL) {
      CloseHandle(read_end);
    }
    return false;
  }

  /* Poll instead of blocking reads: a provider that hangs without closing its output must still
   * hit the timeout. 20 ms granularity is nothing next to a network round trip. */
  const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)BC_PROVIDER_TIMEOUT * 1000;
  bool exited = false;
  for (;;) {
    DWORD available = 0;
    if (!PeekNamedPipe(read_end, NULL, 0, NULL, &available, NULL)) {
      break; /* Broken pipe: every writer is gone and the pipe is empty. */
    }
    if (available > 0) {
      char buffer[4096];
      DWORD n = 0;
      if (!ReadFile(read_end, buffer, available < sizeof(buffer) ? available : sizeof(buffer), &n, NULL)) {
        break;
      }
      bc_keep_output(run, buffer, n);
      continue;
    }
    if (exited) {
      break;
    }
    if (WaitForSingleObject(pi.hProcess, 20) == WAIT_OBJECT_0) {
      exited = true; /* Drain what is left, then stop. */
    }
    else if (GetTickCount64() > deadline) {
      TerminateProcess(pi.hProcess, 1);
      run->timed_out = true;
      break;
    }
  }
  CloseHandle(read_end);
  WaitForSingleObject(pi.hProcess, 5000);
  DWORD exit_code = 1;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  run->exit_code = (int)exit_code;
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return true;
}

#else /* POSIX */

static double bc_now(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static bool bc_run_provider(const char *provider,
                            const char *work_dir,
                            const char *const *args,
                            const int arg_count,
                            const int argc,
                            char **argv,
                            BC_ProviderRun *run)
{
  const int forwarded = argc > 1 ? argc - 1 : 0;
  char **child_args = (char **)calloc((size_t)(arg_count + forwarded + 2), sizeof(char *));
  int fds[2];
  if (child_args == NULL || pipe(fds) != 0) {
    free(child_args);
    return false;
  }
  child_args[0] = (char *)provider;
  for (int i = 0; i < arg_count; i++) {
    child_args[1 + i] = (char *)args[i];
  }
  for (int i = 0; i < forwarded; i++) {
    child_args[1 + arg_count + i] = argv[1 + i];
  }
  fcntl(fds[0], F_SETFD, FD_CLOEXEC);

  const pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    free(child_args);
    return false;
  }
  if (pid == 0) {
    const int null_in = open("/dev/null", O_RDONLY);
    if (null_in >= 0) {
      dup2(null_in, 0);
    }
    dup2(fds[1], 1);
    dup2(fds[1], 2);
    if (chdir(work_dir) == 0) {
      execv(provider, child_args);
    }
    /* Reported through the same pipe, in the provider protocol. */
    dprintf(1, "BCERROR cannot run the key provider '%s': %s\n", provider, strerror(errno));
    _exit(127);
  }
  close(fds[1]);
  free(child_args);

  const double deadline = bc_now() + BC_PROVIDER_TIMEOUT;
  for (;;) {
    const double left = deadline - bc_now();
    if (left <= 0) {
      kill(pid, SIGKILL);
      run->timed_out = true;
      break;
    }
    struct pollfd p = {fds[0], POLLIN, 0};
    const int ready = poll(&p, 1, (int)(left * 1000) + 1);
    if (ready < 0 && errno == EINTR) {
      continue;
    }
    if (ready <= 0) {
      continue; /* Timeout: checked at the top. */
    }
    char buffer[4096];
    const ssize_t n = read(fds[0], buffer, sizeof(buffer));
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      break; /* EOF: the provider (and anything it started) closed its output. */
    }
    bc_keep_output(run, buffer, (size_t)n);
  }
  close(fds[0]);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  run->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
  return true;
}

#endif

/** Collect the protocol lines: up to \a max envelopes in order. \a r_message gets the BCERROR
 * text, else the last other line (a store SDK's own error), so the player sees something better
 * than an exit code. \return the number of envelopes. */
static int bc_parse_output(char *out, uint8_t (*r_envelopes)[BC_ENVELOPE_SIZE], const int max, char *r_message, const size_t message_size)
{
  int count = 0;
  bool explicit_error = false;
  r_message[0] = '\0';
  for (char *line = out; line != NULL && *line != '\0';) {
    char *next = strchr(line, '\n');
    if (next != NULL) {
      *next++ = '\0';
    }
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t')) {
      line[--n] = '\0';
    }
    if (strncmp(line, "BCENVELOPE ", 11) == 0) {
      if (count < max && bc_from_hex(line + 11, r_envelopes[count], BC_ENVELOPE_SIZE)) {
        count++;
      }
    }
    else if (strncmp(line, "BCERROR ", 8) == 0) {
      snprintf(r_message, message_size, "%s", line + 8);
      explicit_error = true;
    }
    else if (n > 0 && !explicit_error) {
      snprintf(r_message, message_size, "%.300s", line);
    }
    line = next;
  }
  return count;
}

/* -------------------------------------------------------------------------------------------- */
/* Key cache: one file per content key id in the user's cache folder. */

static bool bc_cache_path(const uint8_t key_id[BC_KEY_ID_SIZE], char *path, const size_t size)
{
  char base[BC_PATH_MAX];
#ifdef _WIN32
  wchar_t wbase[MAX_PATH];
  const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", wbase, MAX_PATH);
  if (n == 0 || n >= MAX_PATH || !bc_utf8(wbase, base, sizeof(base))) {
    return false;
  }
  for (char *c = base; *c; c++) {
    *c = *c == '\\' ? '/' : *c;
  }
  const char *folder = "UPBGE-BinaryCrypt";
#elif defined(__APPLE__)
  const char *home = getenv("HOME");
  if (home == NULL || home[0] != '/' || (size_t)snprintf(base, sizeof(base), "%s/Library/Caches", home) >= sizeof(base)) {
    return false;
  }
  const char *folder = "upbge-binarycrypt";
#else
  const char *xdg = getenv("XDG_CACHE_HOME");
  const char *home = getenv("HOME");
  if (xdg != NULL && xdg[0] == '/') {
    snprintf(base, sizeof(base), "%s", xdg);
  }
  else if (home == NULL || home[0] != '/' || (size_t)snprintf(base, sizeof(base), "%s/.cache", home) >= sizeof(base)) {
    return false;
  }
  const char *folder = "upbge-binarycrypt";
#endif
  char dir[BC_PATH_MAX];
  char name[2 * BC_KEY_ID_SIZE + 8];
  bc_to_hex(key_id, BC_KEY_ID_SIZE, name);
  strcat(name, ".key");
  return bc_path_join(dir, sizeof(dir), base, folder) && bc_path_join(path, size, dir, name);
}

#ifdef _WIN32

/** DPAPI: only this Windows user on this computer can unprotect it. The entropy ties a blob to its
 * key id, so files cannot be swapped between games. */
static bool bc_cache_dpapi(const uint8_t key_id[BC_KEY_ID_SIZE],
                           const uint8_t *in,
                           const size_t in_size,
                           const bool protect,
                           uint8_t *out,
                           size_t *r_out_size)
{
  uint8_t entropy[sizeof(BC_CACHE_CONTEXT) - 1 + BC_KEY_ID_SIZE];
  memcpy(entropy, BC_CACHE_CONTEXT, sizeof(BC_CACHE_CONTEXT) - 1);
  memcpy(entropy + sizeof(BC_CACHE_CONTEXT) - 1, key_id, BC_KEY_ID_SIZE);
  DATA_BLOB data_in = {(DWORD)in_size, (BYTE *)in};
  DATA_BLOB data_entropy = {sizeof(entropy), entropy};
  DATA_BLOB data_out = {0, NULL};
  const BOOL ok = protect ? CryptProtectData(&data_in, L"UPBGE-BinaryCrypt", &data_entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &data_out) :
                            CryptUnprotectData(&data_in, NULL, &data_entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &data_out);
  const bool fits = ok && data_out.cbData <= *r_out_size;
  if (fits) {
    memcpy(out, data_out.pbData, data_out.cbData);
    *r_out_size = data_out.cbData;
  }
  if (data_out.pbData != NULL) {
    SecureZeroMemory(data_out.pbData, data_out.cbData);
    LocalFree(data_out.pbData);
  }
  return fits;
}

#else

/** Wrapping key: build key, machine id, user id and key id. A cache file copied to another
 * computer or account is useless; recovering the key from a cache file is as hard as recovering
 * the build key from the launcher. */
static bool bc_cache_wrap_key(const uint8_t key_id[BC_KEY_ID_SIZE], uint8_t r_wrap[32])
{
  char machine[128] = "";
  size_t machine_size = 0;
#  ifdef __APPLE__
  uuid_t uuid;
  const struct timespec wait = {5, 0};
  if (gethostuuid(uuid, &wait) != 0) {
    return false;
  }
  memcpy(machine, uuid, sizeof(uuid));
  machine_size = sizeof(uuid);
#  else
  const char *files[] = {"/etc/machine-id", "/var/lib/dbus/machine-id"};
  for (int i = 0; i < 2 && machine_size == 0; i++) {
    FILE *f = fopen(files[i], "rb");
    if (f != NULL) {
      machine_size = fread(machine, 1, sizeof(machine), f);
      fclose(f);
    }
  }
  while (machine_size > 0 && (machine[machine_size - 1] == '\n' || machine[machine_size - 1] == ' ')) {
    machine_size--;
  }
  if (machine_size == 0) {
    return false; /* No stable machine identity: no cache, the key server is asked every time. */
  }
#  endif
  const uint32_t uid = (uint32_t)getuid();
  blake3_hasher hasher;
  blake3_hasher_init_keyed(&hasher, bc_build_key());
  blake3_hasher_update(&hasher, BC_CACHE_CONTEXT, sizeof(BC_CACHE_CONTEXT) - 1);
  blake3_hasher_update(&hasher, machine, machine_size);
  blake3_hasher_update(&hasher, &uid, sizeof(uid));
  blake3_hasher_update(&hasher, key_id, BC_KEY_ID_SIZE);
  blake3_hasher_finalize(&hasher, r_wrap, 32);
  return true;
}

#endif

static bool bc_cache_load(const uint8_t key_id[BC_KEY_ID_SIZE], uint8_t r_key[BC_KEY_SIZE])
{
  char path[BC_PATH_MAX];
  uint8_t data[BC_CACHE_FILE_MAX];
  if (!bc_cache_path(key_id, path, sizeof(path))) {
    return false;
  }
  FILE *f = bc_fopen(path, "rb");
  if (f == NULL) {
    return false;
  }
  const size_t size = fread(data, 1, sizeof(data), f);
  fclose(f);
  bool ok;
#ifdef _WIN32
  uint8_t key[BC_CACHE_FILE_MAX];
  size_t key_size = sizeof(key);
  ok = bc_cache_dpapi(key_id, data, size, false, key, &key_size) && key_size == BC_KEY_SIZE;
  if (ok) {
    memcpy(r_key, key, BC_KEY_SIZE);
  }
  crypto_wipe(key, sizeof(key));
#else
  uint8_t wrap[32];
  ok = size == 24 + BC_KEY_SIZE + 16 && bc_cache_wrap_key(key_id, wrap) &&
       crypto_aead_unlock(r_key, data + 24 + BC_KEY_SIZE, wrap, data, key_id, BC_KEY_ID_SIZE, data + 24, BC_KEY_SIZE) == 0;
  crypto_wipe(wrap, sizeof(wrap));
#endif
  /* The key id check rejects a stale or foreign file even if it decrypted. */
  uint8_t id[BC_KEY_ID_SIZE];
  if (ok) {
    bc_key_id(r_key, id);
    ok = memcmp(id, key_id, BC_KEY_ID_SIZE) == 0;
  }
  if (!ok) {
    crypto_wipe(r_key, BC_KEY_SIZE);
  }
  return ok;
}

/** Best effort: a key that cannot be cached is simply asked for again next time. */
static void bc_cache_store(const uint8_t key_id[BC_KEY_ID_SIZE], const uint8_t key[BC_KEY_SIZE])
{
  char path[BC_PATH_MAX], dir[BC_PATH_MAX], tmp_path[BC_PATH_MAX + 8];
  uint8_t data[BC_CACHE_FILE_MAX];
  size_t size = sizeof(data);
  if (!bc_cache_path(key_id, path, sizeof(path))) {
    return;
  }
  bool ok;
#ifdef _WIN32
  ok = bc_cache_dpapi(key_id, key, BC_KEY_SIZE, true, data, &size);
#else
  uint8_t wrap[32];
  ok = bc_cache_wrap_key(key_id, wrap) && bc_random_bytes(data, 24);
  if (ok) {
    crypto_aead_lock(data + 24, data + 24 + BC_KEY_SIZE, wrap, data, key_id, BC_KEY_ID_SIZE, key, BC_KEY_SIZE);
    size = 24 + BC_KEY_SIZE + 16;
  }
  crypto_wipe(wrap, sizeof(wrap));
#endif
  bc_path_dirname(dir, sizeof(dir), path);
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  FILE *f = ok && bc_mkdir_p(dir) ? bc_fopen(tmp_path, "wb") : NULL;
#ifndef _WIN32
  if (f != NULL) {
    chmod(tmp_path, 0600);
  }
#endif
  ok = f != NULL && fwrite(data, 1, size, f) == size;
  if (f != NULL && fclose(f) != 0) {
    ok = false;
  }
  if (!(ok && bc_rename_replace(tmp_path, path)) && f != NULL) {
    bc_remove(tmp_path);
  }
  crypto_wipe(data, sizeof(data));
}

/* -------------------------------------------------------------------------------------------- */

bool bc_online_keys(const char *game_dir,
                    const BC_Manifest *m,
                    const int argc,
                    char **argv,
                    uint8_t r_keys[][BC_KEY_SIZE],
                    char *err,
                    const size_t err_size)
{
  const bool cache = (m->flags & BC_MANIFEST_KEY_CACHE) != 0;
  int missing[BC_KEYS_MAX];
  int missing_count = 0;
  for (int i = 0; i < m->key_count; i++) {
    if (!cache || !bc_cache_load(m->key_ids[i], r_keys[i])) {
      missing[missing_count++] = i;
    }
  }
  if (missing_count == 0) {
    return true;
  }

  char provider[BC_PATH_MAX];
  char key_ids_hex[BC_KEYS_MAX * (2 * BC_KEY_ID_SIZE + 1)];
  char public_hex[2 * BC_X25519_SIZE + 1];
  uint8_t secret[BC_X25519_SIZE], public_key[BC_X25519_SIZE];
  if (!bc_path_join(provider, sizeof(provider), game_dir, m->provider_path) ||
      !bc_envelope_keypair(secret, public_key))
  {
    snprintf(err, err_size, "cannot prepare the key request");
    return false;
  }
  for (int i = 0; i < missing_count; i++) {
    char *at = key_ids_hex + i * (2 * BC_KEY_ID_SIZE + 1);
    bc_to_hex(m->key_ids[missing[i]], BC_KEY_ID_SIZE, at);
    at[2 * BC_KEY_ID_SIZE] = i + 1 < missing_count ? ',' : '\0';
  }
  bc_to_hex(public_key, BC_X25519_SIZE, public_hex);
  const char *args[3] = {m->key_url[0] != '\0' ? m->key_url : "-", key_ids_hex, public_hex};

  BC_ProviderRun run;
  memset(&run, 0, sizeof(run));
  run.out = (char *)malloc(BC_PROVIDER_OUTPUT_MAX);
  bool ok = run.out != NULL;
  if (ok) {
    run.out[0] = '\0';
#ifdef _WIN32
    (void)argc;
    (void)argv;
    ok = bc_run_provider(provider, game_dir, args, 3, &run);
#else
    ok = bc_run_provider(provider, game_dir, args, 3, argc, argv, &run);
#endif
  }
  static uint8_t envelopes[BC_KEYS_MAX][BC_ENVELOPE_SIZE];
  char message[512];
  int count = 0;
  if (!ok) {
    snprintf(err, err_size, "cannot run the key provider '%s'", provider);
  }
  else if (run.timed_out) {
    snprintf(err, err_size, "the key provider did not answer within %d seconds", BC_PROVIDER_TIMEOUT);
    ok = false;
  }
  /* Envelopes that open are accepted whatever the exit code: some store SDKs crash on shutdown
   * after their work is done. */
  else if ((count = bc_parse_output(run.out, envelopes, missing_count, message, sizeof(message))) != missing_count) {
    if (message[0] != '\0') {
      snprintf(err, err_size, "%s", message);
    }
    else if (count > 0) {
      snprintf(err, err_size, "the key provider returned %d of %d keys", count, missing_count);
    }
    else {
      snprintf(err, err_size, "the key provider failed (exit code %d)", run.exit_code);
    }
    ok = false;
  }
  for (int i = 0; ok && i < missing_count; i++) {
    const int k = missing[i];
    uint8_t id[BC_KEY_ID_SIZE];
    if (!bc_envelope_open(envelopes[i], m->key_ids[k], secret, public_key, r_keys[k])) {
      snprintf(err, err_size, "the key server's answer is not valid for this launch");
      ok = false;
      break;
    }
    bc_key_id(r_keys[k], id);
    if (memcmp(id, m->key_ids[k], BC_KEY_ID_SIZE) != 0) {
      snprintf(err, err_size, "the key server sent the key of another game");
      ok = false;
    }
  }
  crypto_wipe(secret, sizeof(secret));
  free(run.out);
  if (!ok) {
    crypto_wipe(r_keys, (size_t)m->key_count * BC_KEY_SIZE);
    return false;
  }
  for (int i = 0; cache && i < missing_count; i++) {
    bc_cache_store(m->key_ids[missing[i]], r_keys[missing[i]]);
  }
  return true;
}
