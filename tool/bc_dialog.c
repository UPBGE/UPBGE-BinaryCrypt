/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_dialog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc_platform.h"

/** Normalize every separated path in place, dropping empty entries. Normalizing never lengthens
 * a non-empty path, so the write position can never overtake the read position. */
static void bc_normalize_list(char *list)
{
  const char *read = list;
  char *write = list;
  while (*read != '\0') {
    const char *end = strchr(read, BC_DIALOG_SEPARATOR);
    const size_t n = end ? (size_t)(end - read) : strlen(read);
    char path[BC_PATH_MAX];
    if (n > 0 && n < sizeof(path)) {
      memcpy(path, read, n);
      path[n] = '\0';
      bc_path_normalize(path);
      if (write != list) {
        *write++ = BC_DIALOG_SEPARATOR;
      }
      const size_t m = strlen(path);
      memmove(write, path, m);
      write += m;
    }
    read += n;
    if (*read != '\0') {
      read++;
    }
  }
  *write = '\0';
}

/* ============================================================================================ */
#ifdef _WIN32

#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <commdlg.h>
#  include <shellapi.h>
#  include <shlobj.h>

#  define BC_WBUFFER 65536

/** "Blender files (*.blend)\0*.blend\0All files\0*.*\0\0" built for \a extension. */
static void bc_filter(wchar_t *filter, size_t size, const char *extension)
{
  wchar_t ext[64] = L"";
  if (extension != NULL) {
    MultiByteToWideChar(CP_UTF8, 0, extension, -1, ext, 64);
  }
  int n = 0;
  if (ext[0] != L'\0') {
    n += swprintf(filter + n, size - (size_t)n, L"*.%ls", ext) + 1;
    n += swprintf(filter + n, size - (size_t)n, L"*.%ls", ext) + 1;
  }
  n += swprintf(filter + n, size - (size_t)n, L"All files") + 1;
  n += swprintf(filter + n, size - (size_t)n, L"*.*") + 1;
  filter[n] = L'\0';
}

BC_DialogResult bc_dialog_open_files(const char *title,
                                     const char *extension,
                                     bool multiple,
                                     char *out,
                                     size_t size)
{
  static wchar_t buffer[BC_WBUFFER];
  wchar_t filter[256];
  wchar_t *wtitle = bc_utf16(title);
  bc_filter(filter, 256, extension);
  buffer[0] = L'\0';

  OPENFILENAMEW ofn;
  memset(&ofn, 0, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = buffer;
  ofn.nMaxFile = BC_WBUFFER;
  ofn.lpstrTitle = wtitle;
  ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR |
              (multiple ? OFN_ALLOWMULTISELECT : 0);
  const BOOL ok = GetOpenFileNameW(&ofn);
  free(wtitle);
  if (!ok) {
    return BC_DIALOG_CANCELLED;
  }

  /* Multi-select returns "dir\0name1\0name2\0\0"; a single pick returns "full path\0\0". */
  size_t len = 0;
  out[0] = '\0';
  const wchar_t *dir = buffer;
  const wchar_t *name = buffer + wcslen(buffer) + 1;
  if (*name == L'\0') {
    bc_utf8(buffer, out, size);
  }
  else {
    for (; *name != L'\0'; name += wcslen(name) + 1) {
      char dir8[BC_PATH_MAX], name8[BC_PATH_MAX], path[BC_PATH_MAX];
      if (!bc_utf8(dir, dir8, sizeof(dir8)) || !bc_utf8(name, name8, sizeof(name8)) ||
          !bc_path_join(path, sizeof(path), dir8, name8))
      {
        continue;
      }
      const int n = snprintf(out + len, size - len, "%s%s", len ? "\n" : "", path);
      if (n < 0 || (size_t)n >= size - len) {
        break;
      }
      len += (size_t)n;
    }
  }
  bc_normalize_list(out);
  return out[0] ? BC_DIALOG_OK : BC_DIALOG_CANCELLED;
}

BC_DialogResult bc_dialog_save_file(const char *title,
                                    const char *extension,
                                    char *out,
                                    size_t size)
{
  static wchar_t buffer[BC_WBUFFER];
  wchar_t filter[256];
  wchar_t ext[64] = L"";
  wchar_t *wtitle = bc_utf16(title);
  bc_filter(filter, 256, extension);
  if (extension != NULL) {
    MultiByteToWideChar(CP_UTF8, 0, extension, -1, ext, 64);
  }
  buffer[0] = L'\0';

  OPENFILENAMEW ofn;
  memset(&ofn, 0, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = buffer;
  ofn.nMaxFile = BC_WBUFFER;
  ofn.lpstrTitle = wtitle;
  ofn.lpstrDefExt = ext[0] ? ext : NULL;
  ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
  const BOOL ok = GetSaveFileNameW(&ofn);
  free(wtitle);
  if (!ok || !bc_utf8(buffer, out, size)) {
    return BC_DIALOG_CANCELLED;
  }
  bc_path_normalize(out);
  return BC_DIALOG_OK;
}

BC_DialogResult bc_dialog_pick_folder(const char *title, char *out, size_t size)
{
  static bool com_initialized = false;
  if (!com_initialized) {
    /* Required by the resizable "new style" folder browser. */
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    com_initialized = true;
  }
  wchar_t *wtitle = bc_utf16(title);
  BROWSEINFOW info;
  memset(&info, 0, sizeof(info));
  info.lpszTitle = wtitle;
  info.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
  PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&info);
  free(wtitle);
  if (pidl == NULL) {
    return BC_DIALOG_CANCELLED;
  }
  wchar_t path[MAX_PATH];
  const BOOL ok = SHGetPathFromIDListW(pidl, path);
  CoTaskMemFree(pidl);
  if (!ok || !bc_utf8(path, out, size)) {
    return BC_DIALOG_CANCELLED;
  }
  bc_path_normalize(out);
  return BC_DIALOG_OK;
}

/** ShellExecute on \a path from \a dir: the file manager for a folder, the program itself for an
 * executable. */
static bool bc_shell_execute(const char *path, const char *dir)
{
  wchar_t *wpath = bc_utf16(path);
  wchar_t *wdir = dir ? bc_utf16(dir) : NULL;
  /* Values above 32 mean success (an HINSTANCE kept for 16-bit compatibility). */
  const INT_PTR r = wpath ? (INT_PTR)ShellExecuteW(NULL, L"open", wpath, NULL, wdir, SW_SHOWNORMAL) : 0;
  free(wpath);
  free(wdir);
  return r > 32;
}

bool bc_shell_open_folder(const char *folder)
{
  return bc_shell_execute(folder, NULL);
}

bool bc_shell_run(const char *program)
{
  char dir[BC_PATH_MAX];
  bc_path_dirname(dir, sizeof(dir), program);
  return bc_shell_execute(program, dir);
}

/* ============================================================================================ */
bool bc_settings_path(char *out, const size_t size)
{
  wchar_t wbase[MAX_PATH];
  char base[BC_PATH_MAX];
  const DWORD n = GetEnvironmentVariableW(L"APPDATA", wbase, MAX_PATH);
  if (n == 0 || n >= MAX_PATH || !bc_utf8(wbase, base, sizeof(base))) {
    return false;
  }
  bc_path_normalize(base);
  return (size_t)snprintf(out, size, "%s/UPBGE-BinaryCrypt/bc_tool.ini", base) < size;
}

#else /* macOS and Linux: run a helper and read the selection from its output. */

#  include <errno.h>
#  include <fcntl.h>
#  include <sys/wait.h>
#  include <unistd.h>

/** Start argv[0] (looked up in PATH when \a search) as a grandchild in its own session: it
 * outlives the tool and is never left as its zombie. A close-on-exec pipe reports whether the exec
 * itself succeeded. Between fork and exec only async-signal-safe calls. */
static bool bc_spawn_detached(char *const argv[], const char *dir, const bool search)
{
  int status_pipe[2];
  if (pipe(status_pipe) != 0) {
    return false;
  }
  fcntl(status_pipe[1], F_SETFD, FD_CLOEXEC);
  const pid_t pid = fork();
  if (pid == 0) {
    close(status_pipe[0]);
    if (fork() == 0) {
      setsid();
      if (dir == NULL || chdir(dir) == 0) {
        if (search) {
          execvp(argv[0], argv);
        }
        else {
          execv(argv[0], argv);
        }
      }
      const int error = errno;
      (void)!write(status_pipe[1], &error, sizeof(error));
      _exit(127);
    }
    _exit(0);
  }
  close(status_pipe[1]);
  if (pid < 0) {
    close(status_pipe[0]);
    return false;
  }
  int child_status;
  waitpid(pid, &child_status, 0);
  /* End of file: the exec closed the write end. Data: the errno of a failed exec. */
  int error = 0;
  const ssize_t n = read(status_pipe[0], &error, sizeof(error));
  close(status_pipe[0]);
  return n == 0;
}

bool bc_shell_open_folder(const char *folder)
{
#  ifdef __APPLE__
  char *const argv[] = {(char *)"open", (char *)folder, NULL};
#  else
  char *const argv[] = {(char *)"xdg-open", (char *)folder, NULL};
#  endif
  return bc_spawn_detached(argv, NULL, true);
}

bool bc_settings_path(char *out, const size_t size)
{
  const char *home = getenv("HOME");
#  ifdef __APPLE__
  if (home == NULL || home[0] != '/') {
    return false;
  }
  return (size_t)snprintf(out, size, "%s/Library/Application Support/UPBGE-BinaryCrypt/bc_tool.ini", home) < size;
#  else
  const char *xdg = getenv("XDG_CONFIG_HOME");
  if (xdg != NULL && xdg[0] == '/') {
    return (size_t)snprintf(out, size, "%s/upbge-binarycrypt/bc_tool.ini", xdg) < size;
  }
  if (home == NULL || home[0] != '/') {
    return false;
  }
  return (size_t)snprintf(out, size, "%s/.config/upbge-binarycrypt/bc_tool.ini", home) < size;
#  endif
}

bool bc_shell_run(const char *program)
{
  char dir[BC_PATH_MAX];
  bc_path_dirname(dir, sizeof(dir), program);
  char *const argv[] = {(char *)program, NULL};
  return bc_spawn_detached(argv, dir, false);
}

/** Run \a command (constant text only) and capture its output. Returns the exit status, 127 when
 * the helper is not installed. */
static int bc_capture(const char *command, char *out, size_t size)
{
  FILE *pipe = popen(command, "r");
  if (pipe == NULL) {
    return 127;
  }
  size_t len = 0;
  while (len + 1 < size) {
    const size_t n = fread(out + len, 1, size - 1 - len, pipe);
    if (n == 0) {
      break;
    }
    len += n;
  }
  out[len] = '\0';
  const int status = pclose(pipe);
  /* Trailing newline from the helper. */
  while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r')) {
    out[--len] = '\0';
  }
  if (status == -1) {
    return 127;
  }
  return (status >> 8) & 0xff;
}

static BC_DialogResult bc_finish(const int status, char *out)
{
  if (status == 0 && out[0] != '\0') {
    bc_normalize_list(out);
    return BC_DIALOG_OK;
  }
  out[0] = '\0';
  return status == 127 ? BC_DIALOG_UNAVAILABLE : BC_DIALOG_CANCELLED;
}

#  ifdef __APPLE__

BC_DialogResult bc_dialog_open_files(const char *title,
                                     const char *extension,
                                     bool multiple,
                                     char *out,
                                     size_t size)
{
  char type[96] = "";
  if (extension != NULL) {
    snprintf(type, sizeof(type), " of type {\"%s\"}", extension);
  }
  char command[1024];
  snprintf(command,
           sizeof(command),
           "osascript -e 'set fs to choose file with prompt \"%s\"%s%s' "
           "-e 'set out to \"\"' "
           "-e 'repeat with f in (fs as list)' "
           "-e 'set out to out & POSIX path of f & linefeed' "
           "-e 'end repeat' -e 'return out' 2>/dev/null",
           title,
           type,
           multiple ? " with multiple selections allowed" : "");
  return bc_finish(bc_capture(command, out, size), out);
}

BC_DialogResult bc_dialog_save_file(const char *title,
                                    const char *extension,
                                    char *out,
                                    size_t size)
{
  char command[512];
  snprintf(command,
           sizeof(command),
           "osascript -e 'POSIX path of (choose file name with prompt \"%s\")' 2>/dev/null",
           title);
  const BC_DialogResult result = bc_finish(bc_capture(command, out, size), out);
  if (result == BC_DIALOG_OK && extension != NULL) {
    char ext[64];
    snprintf(ext, sizeof(ext), ".%s", extension);
    if (!bc_path_has_extension(out, ext) && strlen(out) + strlen(ext) < size) {
      strcat(out, ext);
    }
  }
  return result;
}

BC_DialogResult bc_dialog_pick_folder(const char *title, char *out, size_t size)
{
  char command[512];
  snprintf(command,
           sizeof(command),
           "osascript -e 'POSIX path of (choose folder with prompt \"%s\")' 2>/dev/null",
           title);
  return bc_finish(bc_capture(command, out, size), out);
}

#  else /* Linux and other Unix: zenity, then kdialog. */

/* Unit separator: zenity joins multiple selections with it, and it cannot appear in our paths
 * list once converted to BC_DIALOG_SEPARATOR. */
#    define BC_ZENITY_SEPARATOR "\x1f"

static void bc_replace_char(char *s, const char from, const char to)
{
  for (; *s; s++) {
    if (*s == from) {
      *s = to;
    }
  }
}

BC_DialogResult bc_dialog_open_files(const char *title,
                                     const char *extension,
                                     bool multiple,
                                     char *out,
                                     size_t size)
{
  char filter[128] = "";
  if (extension != NULL) {
    snprintf(filter, sizeof(filter), " --file-filter='*.%s' --file-filter='*'", extension);
  }
  char command[1024];
  snprintf(command,
           sizeof(command),
           "zenity --file-selection --title='%s'%s%s 2>/dev/null",
           title,
           filter,
           multiple ? " --multiple --separator='" BC_ZENITY_SEPARATOR "'" : "");
  int status = bc_capture(command, out, size);
  if (status == 0) {
    bc_replace_char(out, BC_ZENITY_SEPARATOR[0], BC_DIALOG_SEPARATOR);
  }
  else if (status == 127) {
    snprintf(command,
             sizeof(command),
             "kdialog --title '%s' --getopenfilename . '%s%s'%s 2>/dev/null",
             title,
             extension ? "*." : "*",
             extension ? extension : "",
             multiple ? " --multiple --separate-output" : "");
    status = bc_capture(command, out, size);
  }
  return bc_finish(status, out);
}

BC_DialogResult bc_dialog_save_file(const char *title,
                                    const char *extension,
                                    char *out,
                                    size_t size)
{
  char command[1024];
  snprintf(command,
           sizeof(command),
           "zenity --file-selection --save --title='%s' 2>/dev/null",
           title);
  int status = bc_capture(command, out, size);
  if (status == 127) {
    snprintf(command,
             sizeof(command),
             "kdialog --title '%s' --getsavefilename . 2>/dev/null",
             title);
    status = bc_capture(command, out, size);
  }
  const BC_DialogResult result = bc_finish(status, out);
  if (result == BC_DIALOG_OK && extension != NULL) {
    char ext[64];
    snprintf(ext, sizeof(ext), ".%s", extension);
    if (!bc_path_has_extension(out, ext) && strlen(out) + strlen(ext) < size) {
      strcat(out, ext);
    }
  }
  return result;
}

BC_DialogResult bc_dialog_pick_folder(const char *title, char *out, size_t size)
{
  char command[512];
  snprintf(command,
           sizeof(command),
           "zenity --file-selection --directory --title='%s' 2>/dev/null",
           title);
  int status = bc_capture(command, out, size);
  if (status == 127) {
    snprintf(command,
             sizeof(command),
             "kdialog --title '%s' --getexistingdirectory . 2>/dev/null",
             title);
    status = bc_capture(command, out, size);
  }
  return bc_finish(status, out);
}

#  endif
#endif
