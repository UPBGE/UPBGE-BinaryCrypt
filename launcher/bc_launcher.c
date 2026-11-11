/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Game launcher. bc_tool copies it into the game folder under the game's name with the manifest
 * appended (bc_embed.h): that copy is the one executable a player of the game ever sees.
 *
 * 1. Reads the manifest appended to its own executable and authenticates it with the build key.
 * 2. Hashes the player named by the manifest and refuses to run anything else: a modified player
 *    could dump the decrypted game. With the native code check, also refuses a game folder whose
 *    DLLs or shared libraries (and, at the Python level, Python files) changed since the export
 *    (bc_native.h).
 * 3. Gets the key: the project key masked in the manifest, the content keys from the key server
 *    through the provider (bc_online.h), or the build key itself.
 * 4. Starts the player on the main blend and hands it the key through an inherited pipe
 *    (contract in binarycrypt_format.h), never through the command line or a file.
 *
 * Command line arguments never reach the player: nothing a user types can alter what runs. They
 * only go to the key provider, where stores pass their login tokens.
 * The file that was hashed is the file that is executed: on Linux through fexecve on the same
 * descriptor, on Windows by holding it open without write or delete sharing until the process
 * exists. */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bc_embed.h"
#include "bc_key.h"
#include "bc_native.h"
#include "bc_online.h"
#include "bc_platform.h"
#include "blake3.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/mman.h>
#  include <sys/syscall.h>
#  include <sys/wait.h>
#  include <unistd.h>
extern char **environ;
#endif

#define BC_READ_SIZE (1 << 20)

static int bc_fail(const char *format, ...);

/* -------------------------------------------------------------------------------------------- */
/* Integrity log: when the check refuses the game, a file next to the game executable says what
 * was changed, added or removed (support can ask for it; a store can verify those files). A
 * launch that passes removes it, so it always describes the folder as it is. */

typedef struct BC_Report {
  FILE *log;
  int count;
  char first[BC_PATH_MAX + 16];
} BC_Report;

/** <game executable without its extension>-integrity.log, next to it. */
static bool bc_report_path(const char *exe, char *out, const size_t size)
{
  char base[BC_PATH_MAX];
  snprintf(base, sizeof(base), "%s", exe);
  const size_t n = strlen(base), ext = strlen(bc_exe_extension());
  if (ext > 0 && n > ext && bc_path_has_extension(base, bc_exe_extension())) {
    base[n - ext] = '\0';
  }
  return (size_t)snprintf(out, size, "%s-integrity.log", base) < size;
}

/** Start the log with the time and \a what; NULL where the folder cannot be written. */
static FILE *bc_report_open(const char *path, const char *what)
{
  FILE *f = bc_fopen(path, "w");
  if (f != NULL) {
    char when[32] = "";
    const time_t now = time(NULL);
    const struct tm *t = localtime(&now);
    if (t != NULL) {
      strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", t);
    }
    fprintf(f, "%s  The game did not start: %s since it was exported.\n", when, what);
  }
  return f;
}

static void bc_report_change(void *user, const char *change, const char *path)
{
  BC_Report *r = (BC_Report *)user;
  if (r->count++ == 0) {
    snprintf(r->first, sizeof(r->first), "%s %s", change, path);
  }
  if (r->log != NULL) {
    fprintf(r->log, "%-8s %s\n", change, path);
  }
}

static void bc_report_close(BC_Report *r)
{
  if (r->log != NULL) {
    fprintf(r->log, "Reinstall the game, or have the store verify its files.\n");
    fclose(r->log);
    r->log = NULL;
  }
}

/** The player differs from the export, or is gone: refuse, saying so in the log too. */
static int bc_refuse_player(const char *exe, const BC_Manifest *m, const char *change, const char *message)
{
  char log_path[BC_PATH_MAX];
  BC_Report r = {NULL, 0, ""};
  if (bc_report_path(exe, log_path, sizeof(log_path))) {
    r.log = bc_report_open(log_path, "its player was changed");
  }
  const bool logged = r.log != NULL;
  bc_report_change(&r, change, m->player_path);
  bc_report_close(&r);
  return bc_fail("%s%s%s", message, logged ? "; see " : "", logged ? bc_path_basename(log_path) : "");
}

/** The code of the game folder differs from the export: refuse, naming the files. The export's
 * records (BC_NATIVE_RECORD, next to the player) count only when they hash to the manifest's
 * digest; then a second walk of the folder, now, tells which file differs. */
static int bc_refuse_code(const char *dir, const char *exe, const BC_Manifest *m, const char *const *skip, const bool python)
{
  const char *kind = python ? "library, program or Python file" : "library or program";
  char log_path[BC_PATH_MAX], player_file[BC_PATH_MAX], player_dir[BC_PATH_MAX] = "", record[BC_PATH_MAX];
  BC_Report r = {NULL, 0, ""};
  if (bc_report_path(exe, log_path, sizeof(log_path))) {
    r.log = bc_report_open(log_path, "files of its folder were changed, added or removed");
  }
  const bool logged = r.log != NULL;

  uint8_t *reference = NULL, *current = NULL;
  size_t reference_size = 0, current_size = 0;
  uint64_t size = 0, mtime = 0;
  bool listed = false;
  if (bc_path_join(player_file, sizeof(player_file), dir, m->player_path)) {
    bc_path_dirname(player_dir, sizeof(player_dir), player_file);
  }
  if (player_dir[0] != '\0' && bc_path_join(record, sizeof(record), player_dir, BC_NATIVE_RECORD) && bc_file_stat(record, &size, &mtime) &&
      size <= BC_NATIVE_RECORD_MAX && (reference = (uint8_t *)malloc((size_t)size + 1)) != NULL)
  {
    FILE *f = bc_fopen(record, "rb");
    uint8_t digest[BC_NATIVE_DIGEST_SIZE];
    reference_size = (size_t)size;
    listed = f != NULL && fread(reference, 1, reference_size, f) == reference_size;
    if (f != NULL) {
      fclose(f);
    }
    if (listed) {
      bc_native_records_digest(reference, reference_size, digest);
      listed = crypto_verify32(digest, m->native_digest) == 0 &&
               bc_native_digest_records(dir, skip, 2, python, digest, NULL, &current, &current_size) &&
               bc_native_compare(reference, reference_size, current, current_size, bc_report_change, &r) > 0;
    }
  }
  free(reference);
  free(current);
  if (!listed && r.log != NULL) {
    fprintf(r.log, "Which file cannot be told: the list of the exported files (%s) is missing or was changed.\n", BC_NATIVE_RECORD);
  }
  bc_report_close(&r);
  char more[48] = "";
  if (listed && r.count > 1) {
    snprintf(more, sizeof(more), ", and %d more", r.count - 1);
  }
  return bc_fail("cannot start the game: a %s of the game folder was changed, added or removed since the game was "
                 "exported%s%s%s%s%s%s",
                 kind,
                 listed ? " (" : "",
                 listed ? r.first : "",
                 more,
                 listed ? ")" : "",
                 logged ? "; see " : "",
                 logged ? bc_path_basename(log_path) : "");
}

static int bc_fail(const char *format, ...)
{
  char message[2 * BC_PATH_MAX];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
#ifdef _WIN32
  /* Built as a GUI application (no console window). Started by a script with stderr redirected,
   * report there; started by a double click (no standard handles), show a message box. */
  HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
  if (err != NULL && err != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    WriteFile(err, "launcher: ", 10, &written, NULL);
    WriteFile(err, message, (DWORD)strlen(message), &written, NULL);
    WriteFile(err, "\r\n", 2, &written, NULL);
    return 1;
  }
  wchar_t *wmessage = bc_utf16(message);
  MessageBoxW(NULL, wmessage ? wmessage : L"Error", L"Game launcher", MB_OK | MB_ICONERROR);
  free(wmessage);
#else
  fprintf(stderr, "launcher: %s\n", message);
#endif
  return 1;
}

/* -------------------------------------------------------------------------------------------- */
/* Player file: opened once, hashed, then executed from the same open file. */

#ifdef _WIN32
typedef HANDLE BC_PlayerFile;
#  define BC_PLAYER_INVALID INVALID_HANDLE_VALUE
#else
typedef int BC_PlayerFile;
#  define BC_PLAYER_INVALID (-1)
#endif

static BC_PlayerFile bc_player_open(const char *path)
{
#ifdef _WIN32
  wchar_t *wpath = bc_utf16(path);
  /* FILE_SHARE_READ only: nobody can write, rename or delete the player while it is open. */
  HANDLE h = wpath ? CreateFileW(wpath,
                                 GENERIC_READ,
                                 FILE_SHARE_READ,
                                 NULL,
                                 OPEN_EXISTING,
                                 FILE_FLAG_SEQUENTIAL_SCAN,
                                 NULL) :
                     INVALID_HANDLE_VALUE;
  free(wpath);
  return h;
#else
  return open(path, O_RDONLY | O_CLOEXEC);
#endif
}

static void bc_player_close(BC_PlayerFile file)
{
#ifdef _WIN32
  CloseHandle(file);
#else
  close(file);
#endif
}

static bool bc_player_hash(BC_PlayerFile file, uint8_t hash[BC_PLAYER_HASH_SIZE])
{
  uint8_t *buffer = (uint8_t *)malloc(BC_READ_SIZE);
  if (buffer == NULL) {
    return false;
  }
  /* Static: the hasher's chunk stack is about 2 KiB. Single threaded. */
  static blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  bool ok = true;
  for (;;) {
#ifdef _WIN32
    DWORD n = 0;
    if (!ReadFile(file, buffer, BC_READ_SIZE, &n, NULL)) {
      ok = false;
      break;
    }
#else
    const ssize_t n = read(file, buffer, BC_READ_SIZE);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      ok = false;
      break;
    }
#endif
    if (n == 0) {
      break;
    }
    blake3_hasher_update(&hasher, buffer, (size_t)n);
  }
  blake3_hasher_finalize(&hasher, hash, BC_PLAYER_HASH_SIZE);
  free(buffer);
  return ok;
}

/* -------------------------------------------------------------------------------------------- */
/* Start the player and hand over the key. Returns the player's exit code, or -1 on failure. */

/* The player's -g options for the manifest's debug displays: "-g <name> = 1" each. */
#define BC_SHOW_OPTION_COUNT 4
static const struct {
  uint16_t bit;
  const char *name;
#ifdef _WIN32
  const wchar_t *wname;
#endif
} bc_show_options[BC_SHOW_OPTION_COUNT] = {
#ifdef _WIN32
#  define BC_SHOW(bit, name) {bit, name, L##name}
#else
#  define BC_SHOW(bit, name) {bit, name}
#endif
    BC_SHOW(BC_MANIFEST_SHOW_FRAMERATE, "show_framerate"),
    BC_SHOW(BC_MANIFEST_SHOW_PROFILE, "show_profile"),
    BC_SHOW(BC_MANIFEST_SHOW_PHYSICS, "show_physics"),
    BC_SHOW(BC_MANIFEST_SHOW_PROPERTIES, "show_properties"),
#undef BC_SHOW
};

#ifdef _WIN32
/** Append \a arg quoted so that CommandLineToArgvW yields it back unchanged. */
bool bc_append_quoted(wchar_t *cmd, size_t size, size_t *len, const wchar_t *arg);
bool bc_append_quoted(wchar_t *cmd, size_t size, size_t *len, const wchar_t *arg)
{
#  define BC_PUT(c) \
    do { \
      if (*len + 1 >= size) { \
        return false; \
      } \
      cmd[(*len)++] = (c); \
    } while (0)
  if (*len > 0) {
    BC_PUT(L' ');
  }
  BC_PUT(L'"');
  for (const wchar_t *c = arg;; c++) {
    size_t backslashes = 0;
    while (*c == L'\\') {
      backslashes++;
      c++;
    }
    /* Backslashes are literal unless they precede a quote: double them there. */
    const size_t repeat = (*c == L'\0') ? 2 * backslashes :
                          (*c == L'"')  ? 2 * backslashes + 1 :
                                          backslashes;
    for (size_t i = 0; i < repeat; i++) {
      BC_PUT(L'\\');
    }
    if (*c == L'\0') {
      break;
    }
    BC_PUT(*c);
  }
  BC_PUT(L'"');
  cmd[*len] = L'\0';
  return true;
#  undef BC_PUT
}

/** CreateProcessW where the child inherits exactly \a handles (PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
 * not every inheritable handle of this process: a store client or a script that started the game
 * may have left handles of its own inheritable, and those must not reach the player. NULL,
 * invalid and repeated entries are dropped (a repeated entry fails CreateProcessW); every other
 * entry must be inheritable. No entry left: nothing is inherited. */
BOOL bc_create_process(const wchar_t *app,
                       wchar_t *cmd,
                       DWORD flags,
                       const wchar_t *dir,
                       const STARTUPINFOW *si,
                       const HANDLE *handles,
                       int count,
                       PROCESS_INFORMATION *pi);
BOOL bc_create_process(const wchar_t *app,
                       wchar_t *cmd,
                       DWORD flags,
                       const wchar_t *dir,
                       const STARTUPINFOW *si,
                       const HANDLE *handles,
                       int count,
                       PROCESS_INFORMATION *pi)
{
  HANDLE list[4];
  DWORD n = 0;
  for (int i = 0; i < count && n < 4; i++) {
    bool skip = handles[i] == NULL || handles[i] == INVALID_HANDLE_VALUE;
    for (DWORD j = 0; j < n && !skip; j++) {
      skip = list[j] == handles[i];
    }
    if (!skip) {
      list[n++] = handles[i];
    }
  }
  STARTUPINFOEXW six;
  memset(&six, 0, sizeof(six));
  six.StartupInfo = *si;
  if (n == 0) {
    six.StartupInfo.cb = sizeof(STARTUPINFOW);
    return CreateProcessW(app, cmd, NULL, NULL, FALSE, flags, NULL, dir, &six.StartupInfo, pi);
  }
  SIZE_T attr_size = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
  six.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
  if (six.lpAttributeList == NULL) {
    return FALSE;
  }
  BOOL ok = InitializeProcThreadAttributeList(six.lpAttributeList, 1, 0, &attr_size);
  if (ok) {
    six.StartupInfo.cb = sizeof(six);
    ok = UpdateProcThreadAttribute(six.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, n * sizeof(HANDLE), NULL, NULL) &&
         CreateProcessW(app, cmd, NULL, NULL, TRUE, flags | EXTENDED_STARTUPINFO_PRESENT, NULL, dir, &six.StartupInfo, pi);
    DeleteProcThreadAttributeList(six.lpAttributeList);
  }
  free(six.lpAttributeList);
  return ok;
}

static void bc_to_backslashes(wchar_t *s)
{
  for (; *s; s++) {
    if (*s == L'/') {
      *s = L'\\';
    }
  }
}

static int bc_run_player(BC_PlayerFile player_file,
                         const char *player_path,
                         const char *title,
                         const uint16_t show,
                         const char *main_path,
                         const char *work_dir,
                         uint8_t *keys,
                         const int key_count)
{
  (void)player_file; /* Held open by the caller until the process exists. */
  wchar_t *wplayer = bc_utf16(player_path);
  wchar_t *wtitle = bc_utf16(title);
  wchar_t *wmain = bc_utf16(main_path);
  wchar_t *wdir = bc_utf16(work_dir);
  static wchar_t cmd[32768];
  size_t len = 0;
  int result = -1;
  HANDLE read_end = NULL, write_end = NULL;

  if (wplayer == NULL || wtitle == NULL || wmain == NULL || wdir == NULL) {
    goto cleanup;
  }
  bc_to_backslashes(wplayer);
  bc_to_backslashes(wmain);
  bc_to_backslashes(wdir);
  if (!bc_append_quoted(cmd, 32768, &len, wplayer) || !bc_append_quoted(cmd, 32768, &len, L"-t") ||
      !bc_append_quoted(cmd, 32768, &len, wtitle))
  {
    goto cleanup;
  }
  for (int i = 0; i < BC_SHOW_OPTION_COUNT; i++) {
    if ((show & bc_show_options[i].bit) &&
        (!bc_append_quoted(cmd, 32768, &len, L"-g") || !bc_append_quoted(cmd, 32768, &len, bc_show_options[i].wname) ||
         !bc_append_quoted(cmd, 32768, &len, L"=") || !bc_append_quoted(cmd, 32768, &len, L"1")))
    {
      goto cleanup;
    }
  }
  if (!bc_append_quoted(cmd, 32768, &len, wmain)) {
    goto cleanup;
  }

  /* Only the read end is inheritable; the variable carries its handle value to the child. */
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  if (!CreatePipe(&read_end, &write_end, &sa, 0) ||
      !SetHandleInformation(write_end, HANDLE_FLAG_INHERIT, 0))
  {
    goto cleanup;
  }
  wchar_t value[32];
  swprintf(value, 32, L"%llu", (unsigned long long)(uintptr_t)read_end);
  SetEnvironmentVariableW(L"" BC_KEY_PIPE_ENV, value);

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  /* A WIN32 subsystem launcher only has standard handles when its parent redirected them to a
   * pipe or a file (log capture, store clients, test harnesses). Hand those to the player so its
   * output lands there; otherwise the player gets its own console, exactly as if double clicked
   * (and hides it itself). */
  const DWORD std_ids[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
  HANDLE std_handles[3];
  HANDLE inherited[4] = {read_end, NULL, NULL, NULL};
  bool redirected = false;
  for (int i = 0; i < 3; i++) {
    std_handles[i] = GetStdHandle(std_ids[i]);
    const bool valid = std_handles[i] != NULL && std_handles[i] != INVALID_HANDLE_VALUE;
    const DWORD type = valid ? GetFileType(std_handles[i]) : FILE_TYPE_UNKNOWN;
    if (i > 0 && (type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK)) {
      redirected = true;
    }
  }
  if (redirected) {
    for (int i = 0; i < 3; i++) {
      if (std_handles[i] != NULL && std_handles[i] != INVALID_HANDLE_VALUE) {
        SetHandleInformation(std_handles[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
      }
    }
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = std_handles[0];
    si.hStdOutput = std_handles[1];
    si.hStdError = std_handles[2];
    memcpy(inherited + 1, std_handles, sizeof(std_handles));
  }
  /* The player is a console program: without the console option it runs without one, so no
   * console window opens behind the game (its output still reaches redirected handles). */
  const DWORD creation = (show & BC_MANIFEST_SHOW_CONSOLE) ? 0 : CREATE_NO_WINDOW;
  const BOOL started = bc_create_process(wplayer, cmd, creation, wdir, &si, inherited, 4, &pi);
  SetEnvironmentVariableW(L"" BC_KEY_PIPE_ENV, NULL);
  CloseHandle(read_end);
  read_end = NULL;
  if (!started) {
    goto cleanup;
  }
  /* The hand-off header, then the keys straight from their locked table. */
  const size_t keys_size = (size_t)key_count * BC_KEY_SIZE;
  uint8_t handoff[BC_HANDOFF_HEADER_SIZE];
  bc_handoff_header_write((uint16_t)key_count, handoff);
  DWORD written = 0;
  WriteFile(write_end, handoff, sizeof(handoff), &written, NULL);
  WriteFile(write_end, keys, (DWORD)keys_size, &written, NULL);
  crypto_wipe(keys, keys_size); /* The player has them now; nothing here needs them any more. */
  CloseHandle(write_end);
  write_end = NULL;

  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exit_code = 1;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  result = (int)exit_code;

cleanup:
  if (read_end) {
    CloseHandle(read_end);
  }
  if (write_end) {
    CloseHandle(write_end);
  }
  free(wplayer);
  free(wtitle);
  free(wmain);
  free(wdir);
  return result;
}

#else /* POSIX */

/** Mark every descriptor above the standard streams close-on-exec except \a keep: whatever this
 * process inherited from its own parent (a store client, a shell script) must not reach the
 * player. One close_range call on Linux 5.11+, else one fcntl per descriptor slot. */
static void bc_cloexec_all_but(const int keep)
{
#  if defined(__linux__) && defined(SYS_close_range)
  if (syscall(SYS_close_range, 3u, ~0u, 4u /* CLOSE_RANGE_CLOEXEC */) == 0) {
    fcntl(keep, F_SETFD, 0);
    return;
  }
#  endif
  long max = sysconf(_SC_OPEN_MAX);
  if (max < 0 || max > 65536) {
    max = 65536;
  }
  for (int fd = 3; fd < (int)max; fd++) {
    if (fd != keep) {
      fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
  }
}

static int bc_run_player(BC_PlayerFile player_file,
                         const char *player_path,
                         const char *title,
                         const uint16_t show,
                         const char *main_path,
                         const char *work_dir,
                         uint8_t *keys,
                         const int key_count)
{
  /* fds: key pipe, the read end is inherited by the player. status: close-on-exec pipe that
   * reports a failed exec (child writes errno) or closes silently once exec succeeded. */
  int fds[2], status_fds[2];
  if (pipe(fds) != 0) {
    return -1;
  }
  if (pipe(status_fds) != 0) {
    close(fds[0]);
    close(fds[1]);
    return -1;
  }
  /* The write end of the key pipe must not leak into the player. */
  fcntl(fds[1], F_SETFD, FD_CLOEXEC);
  fcntl(status_fds[0], F_SETFD, FD_CLOEXEC);
  fcntl(status_fds[1], F_SETFD, FD_CLOEXEC);
  char value[32];
  snprintf(value, sizeof(value), "%d", fds[0]);

  const pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    close(status_fds[0]);
    close(status_fds[1]);
    return -1;
  }
  if (pid == 0) {
    /* Child. Single-threaded parent, so setenv after fork is safe here. */
    close(fds[1]);
    close(status_fds[0]);
    bc_cloexec_all_but(fds[0]);
    setenv(BC_KEY_PIPE_ENV, value, 1);
    if (chdir(work_dir) == 0) {
      /* player -t title [-g name = 1]... main: at most 3 + 4 per option + 2 entries. */
      char *args[3 + 4 * BC_SHOW_OPTION_COUNT + 2] = {(char *)player_path, (char *)"-t", (char *)title};
      int n = 3;
      for (int i = 0; i < BC_SHOW_OPTION_COUNT; i++) {
        if (show & bc_show_options[i].bit) {
          args[n++] = (char *)"-g";
          args[n++] = (char *)bc_show_options[i].name;
          args[n++] = (char *)"=";
          args[n++] = (char *)"1";
        }
      }
      args[n++] = (char *)main_path;
      args[n] = NULL;
#  ifdef __linux__
      /* Execute the very file that was hashed, not whatever the path names by now. */
      fexecve(player_file, args, environ);
#  else
      (void)player_file;
      execv(player_path, args);
#  endif
    }
    const int error = errno;
    ssize_t ignored = write(status_fds[1], &error, sizeof(error));
    (void)ignored;
    _exit(127);
  }

  close(fds[0]);
  close(status_fds[1]);
  /* Wait for the exec outcome: the key only goes to a process that is running the player. */
  int exec_error = 0;
  ssize_t status_read;
  while ((status_read = read(status_fds[0], &exec_error, sizeof(exec_error))) < 0 &&
         errno == EINTR)
  {
  }
  close(status_fds[0]);
  if (status_read > 0) {
    close(fds[1]);
    waitpid(pid, NULL, 0);
    return -1;
  }

  /* If the player dies before reading, the write must fail instead of killing the launcher. */
  signal(SIGPIPE, SIG_IGN);
  /* The hand-off header, then the keys straight from their locked table. */
  const size_t keys_size = (size_t)key_count * BC_KEY_SIZE;
  uint8_t handoff[BC_HANDOFF_HEADER_SIZE];
  bc_handoff_header_write((uint16_t)key_count, handoff);
  const struct {
    const uint8_t *data;
    size_t size;
  } parts[2] = {{handoff, sizeof(handoff)}, {keys, keys_size}};
  for (int part = 0; part < 2; part++) {
    size_t done = 0;
    while (done < parts[part].size) {
      const ssize_t n = write(fds[1], parts[part].data + done, parts[part].size - done);
      if (n > 0) {
        done += (size_t)n;
      }
      else if (n < 0 && errno == EINTR) {
        continue;
      }
      else {
        break;
      }
    }
  }
  crypto_wipe(keys, keys_size); /* The player has them now; nothing here needs them any more. */
  close(fds[1]);

  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return -1;
    }
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1;
}

#endif

/* -------------------------------------------------------------------------------------------- */

#define BC_KEY_TABLE_SIZE ((size_t)BC_KEYS_MAX * BC_KEY_SIZE)

/** A page for the keys: locked out of swap and the page file and, on Linux, out of core dumps
 * (same treatment as the player's key table). Best effort: without the privilege it is merely
 * pageable. They only live here until the pipe write, which wipes them. */
static uint8_t (*bc_key_table_alloc(void))[BC_KEY_SIZE]
{
#ifdef _WIN32
  void *page = VirtualAlloc(NULL, BC_KEY_TABLE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (page != NULL) {
    VirtualLock(page, BC_KEY_TABLE_SIZE);
  }
#else
  void *page = mmap(NULL, BC_KEY_TABLE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    return NULL;
  }
  mlock(page, BC_KEY_TABLE_SIZE);
#  ifdef MADV_DONTDUMP
  madvise(page, BC_KEY_TABLE_SIZE, MADV_DONTDUMP);
#  endif
#endif
  return (uint8_t(*)[BC_KEY_SIZE])page;
}

int main(int argc, char **argv)
{
  char exe[BC_PATH_MAX];
  char dir[BC_PATH_MAX];
  if (!bc_exe_path(exe, sizeof(exe))) {
    return bc_fail("cannot locate the game executable");
  }
  bc_path_dirname(dir, sizeof(dir), exe);

  /* Embedded manifest first. The external file is only consulted when the executable carries
   * none: a damaged embedded manifest is an error, never a reason to trust a file instead. */
  BC_Manifest manifest;
  const char *source = exe;
  char manifest_file[BC_PATH_MAX];
  BC_ManifestResult result = bc_embed_read(exe, bc_build_key(), &manifest);
  if (result == BC_MANIFEST_MISSING &&
      bc_path_join(manifest_file, sizeof(manifest_file), dir, BC_MANIFEST_FILENAME))
  {
    source = manifest_file;
    result = bc_manifest_file_read(manifest_file, bc_build_key(), &manifest);
  }
  if (result != BC_MANIFEST_OK) {
    return bc_fail("cannot start the game: %s (%s)", bc_manifest_result_string(result), source);
  }

  char player_path[BC_PATH_MAX];
  char main_path[BC_PATH_MAX];
  if (!bc_path_join(player_path, sizeof(player_path), dir, manifest.player_path) ||
      !bc_path_join(main_path, sizeof(main_path), dir, manifest.main_path))
  {
    return bc_fail("invalid paths in the manifest");
  }
  if (!bc_is_file(main_path)) {
    return bc_fail("cannot start the game: '%s' is missing", main_path);
  }

  BC_PlayerFile player = bc_player_open(player_path);
  char message[2 * BC_PATH_MAX];
  if (player == BC_PLAYER_INVALID) {
    snprintf(message, sizeof(message), "cannot start the game: the player '%s' is missing", player_path);
    return bc_refuse_player(exe, &manifest, "removed", message);
  }
  uint8_t hash[BC_PLAYER_HASH_SIZE];
  if (!bc_player_hash(player, hash)) {
    bc_player_close(player);
    return bc_fail("cannot read the player '%s'", player_path);
  }
  if (crypto_verify32(hash, manifest.player_hash) != 0) {
    bc_player_close(player);
    snprintf(message, sizeof(message), "cannot start the game: the player '%s' has been modified or replaced", player_path);
    return bc_refuse_player(exe, &manifest, "changed", message);
  }
  const bool python_check = (manifest.flags & BC_MANIFEST_PYTHON_CHECK) != 0;
  /* Every checked file stays open until the player exits (Windows: nobody can replace it). */
  BC_NativeHold hold = {NULL, 0, 0};
  if (manifest.flags & BC_MANIFEST_NATIVE_DIGEST) {
    /* The player loads more code from this folder (its libraries, Python extension modules and,
     * at the Python level, Python modules), all of it running with the keys in memory. */
    char exe_rel[BC_PATH_MAX];
    const char *skip[2] = {exe_rel, manifest.player_path};
    uint8_t digest[BC_NATIVE_DIGEST_SIZE];
    static BC_NativeScan scan;
    if (!bc_path_relative(exe_rel, sizeof(exe_rel), dir, exe) ||
        !bc_native_digest_held(dir, skip, 2, python_check, digest, &scan, &hold))
    {
      bc_native_release(&hold);
      bc_player_close(player);
      if (scan.locked[0] != '\0') {
        /* The export left no bytecode and the player could not have written this one here. */
        return bc_fail("cannot start the game: '%s' cannot be removed (Python bytecode that was not "
                       "part of the game; reinstall the game)",
                       scan.locked);
      }
      return bc_fail("cannot read the game folder '%s'", dir);
    }
    if (crypto_verify32(digest, manifest.native_digest) != 0) {
      bc_native_release(&hold);
      bc_player_close(player);
      return bc_refuse_code(dir, exe, &manifest, skip, python_check);
    }
  }
  /* Checked: a log of an earlier refusal no longer describes this folder. */
  {
    char log_path[BC_PATH_MAX];
    if (bc_report_path(exe, log_path, sizeof(log_path))) {
      bc_remove(log_path);
    }
  }

  /* The keys of every file of the game, in one write: the player picks per file by key id. */
  uint8_t(*keys)[BC_KEY_SIZE] = bc_key_table_alloc();
  if (keys == NULL) {
    bc_native_release(&hold);
    bc_player_close(player);
    return bc_fail("cannot start the game: out of memory");
  }
  int key_count = 1;
  if (manifest.flags & BC_MANIFEST_ONLINE_KEY) {
    char err[1024];
    key_count = manifest.key_count;
    if (!bc_online_keys(dir, &manifest, argc, argv, keys, err, sizeof(err))) {
      crypto_wipe(keys, BC_KEY_TABLE_SIZE);
      bc_native_release(&hold);
      bc_player_close(player);
      return bc_fail("cannot start the game: %s", err);
    }
  }
  else if (manifest.flags & BC_MANIFEST_PROJECT_KEY) {
    uint8_t mask[BC_KEY_SIZE], id[BC_KEY_ID_SIZE];
    bc_manifest_key_mask(bc_build_key(), &manifest, mask);
    for (int i = 0; i < BC_KEY_SIZE; i++) {
      keys[0][i] = manifest.masked_key[i] ^ mask[i];
    }
    crypto_wipe(mask, sizeof(mask));
    bc_key_id(keys[0], id);
    if (memcmp(id, manifest.key_ids[0], BC_KEY_ID_SIZE) != 0) {
      crypto_wipe(keys, BC_KEY_TABLE_SIZE);
      bc_native_release(&hold);
      bc_player_close(player);
      return bc_fail("cannot start the game: %s", bc_manifest_result_string(BC_MANIFEST_BAD_FORMAT));
    }
  }
  else {
    memcpy(keys[0], bc_build_key(), BC_KEY_SIZE);
  }
  bc_build_key_forget();
  /* The player's window shows the game's name, the executable's: a renamed game shows its new
   * name, whichever .blend file the game loads. */
  char title[BC_PATH_MAX];
  snprintf(title, sizeof(title), "%s", bc_path_basename(exe));
  const size_t title_len = strlen(title), ext_len = strlen(bc_exe_extension());
  if (ext_len > 0 && title_len > ext_len && bc_path_has_extension(title, bc_exe_extension())) {
    title[title_len - ext_len] = '\0';
  }
  const int exit_code = bc_run_player(player, player_path, title, manifest.options, main_path, dir, &keys[0][0], key_count);
  crypto_wipe(keys, BC_KEY_TABLE_SIZE);
  bc_native_release(&hold);
  bc_player_close(player);
  if (python_check) {
    /* Leave no bytecode behind: a test run followed by an upload must not ship any (the next
     * launch of a read-only install would refuse it). */
    bc_remove_bytecode(dir, NULL);
  }
  if (exit_code < 0) {
    return bc_fail("cannot start the player '%s'", player_path);
  }
  return exit_code;
}
