/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_platform.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <dirent.h>
#  include <errno.h>
#  include <sys/stat.h>
#  include <time.h>
#  include <unistd.h>
#  ifdef __APPLE__
#    include <mach-o/dyld.h>
#  else
#    include <sys/random.h>
#  endif
#endif

/* -------------------------------------------------------------------------------------------- */
/* Windows text conversion */

#ifdef _WIN32
wchar_t *bc_utf16(const char *utf8)
{
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
  if (n <= 0) {
    return NULL;
  }
  wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * (size_t)n);
  if (w != NULL && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, w, n) <= 0) {
    free(w);
    return NULL;
  }
  return w;
}

bool bc_utf8(const wchar_t *utf16, char *out, size_t size)
{
  return WideCharToMultiByte(CP_UTF8, 0, utf16, -1, out, (int)size, NULL, NULL) > 0;
}
#endif

/* -------------------------------------------------------------------------------------------- */
/* Randomness and time */

bool bc_random_bytes(void *dst, size_t size)
{
#ifdef _WIN32
  return BCryptGenRandom(NULL, (PUCHAR)dst, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(__APPLE__)
  arc4random_buf(dst, size);
  return true;
#else
  uint8_t *p = (uint8_t *)dst;
  while (size > 0) {
    const ssize_t n = getrandom(p, size, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    p += n;
    size -= (size_t)n;
  }
  return true;
#endif
}

double bc_time_seconds(void)
{
#ifdef _WIN32
  LARGE_INTEGER frequency, counter;
  QueryPerformanceFrequency(&frequency);
  QueryPerformanceCounter(&counter);
  return (double)counter.QuadPart / (double)frequency.QuadPart;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}

/* -------------------------------------------------------------------------------------------- */
/* Files */

FILE *bc_fopen(const char *path, const char *mode)
{
#ifdef _WIN32
  wchar_t *wpath = bc_utf16(path);
  wchar_t *wmode = bc_utf16(mode);
  FILE *f = (wpath && wmode) ? _wfopen(wpath, wmode) : NULL;
  free(wpath);
  free(wmode);
  return f;
#else
  return fopen(path, mode);
#endif
}

bool bc_file_stat(const char *path, uint64_t *r_size, uint64_t *r_mtime)
{
#ifdef _WIN32
  wchar_t *wpath = bc_utf16(path);
  WIN32_FILE_ATTRIBUTE_DATA data = {0};
  const bool ok = wpath && GetFileAttributesExW(wpath, GetFileExInfoStandard, &data) &&
                  !(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
  free(wpath);
  if (ok) {
    *r_size = ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
    /* FILETIME counts 100 ns ticks from 1601: rebase on 1970, the POSIX epoch. */
    const uint64_t ticks = ((uint64_t)data.ftLastWriteTime.dwHighDateTime << 32) | data.ftLastWriteTime.dwLowDateTime;
    *r_mtime = ticks >= 116444736000000000ull ? (ticks - 116444736000000000ull) * 100u : 0;
  }
  return ok;
#else
  struct stat st;
  if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
    return false;
  }
  *r_size = (uint64_t)st.st_size;
#  ifdef __APPLE__
  const struct timespec t = st.st_mtimespec;
#  else
  const struct timespec t = st.st_mtim;
#  endif
  *r_mtime = t.tv_sec < 0 ? 0 : (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
  return true;
#endif
}

bool bc_file_size(const char *path, uint64_t *r_size)
{
  uint64_t mtime;
  return bc_file_stat(path, r_size, &mtime);
}

#ifdef _WIN32
static DWORD bc_attributes(const char *path)
{
  wchar_t *wpath = bc_utf16(path);
  const DWORD attributes = wpath ? GetFileAttributesW(wpath) : INVALID_FILE_ATTRIBUTES;
  free(wpath);
  return attributes;
}
#endif

bool bc_is_file(const char *path)
{
#ifdef _WIN32
  const DWORD a = bc_attributes(path);
  return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

bool bc_is_dir(const char *path)
{
#ifdef _WIN32
  const DWORD a = bc_attributes(path);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static bool bc_mkdir_one(const char *dir)
{
#ifdef _WIN32
  wchar_t *wdir = bc_utf16(dir);
  const bool ok = wdir && (CreateDirectoryW(wdir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS);
  free(wdir);
  return ok;
#else
  return mkdir(dir, 0755) == 0 || errno == EEXIST;
#endif
}

bool bc_mkdir_p(const char *dir)
{
  char path[BC_PATH_MAX];
  if (strlen(dir) >= sizeof(path)) {
    return false;
  }
  strcpy(path, dir);
  bc_path_normalize(path);
  /* Create every prefix that ends at a separator, then the full path. The root ("/", "C:/") and
   * UNC server names fail harmlessly or already exist. */
  for (char *p = path + 1; *p != '\0'; p++) {
    if (*p == '/') {
      *p = '\0';
      if (!(p > path && p[-1] == ':') && !bc_is_dir(path)) {
        bc_mkdir_one(path);
      }
      *p = '/';
    }
  }
  return bc_mkdir_one(path) && bc_is_dir(path);
}

bool bc_rename_replace(const char *from, const char *to)
{
#ifdef _WIN32
  wchar_t *wfrom = bc_utf16(from);
  wchar_t *wto = bc_utf16(to);
  const bool ok = wfrom && wto && MoveFileExW(wfrom, wto, MOVEFILE_REPLACE_EXISTING);
  free(wfrom);
  free(wto);
  return ok;
#else
  return rename(from, to) == 0;
#endif
}

bool bc_remove(const char *path)
{
#ifdef _WIN32
  wchar_t *wpath = bc_utf16(path);
  const bool ok = wpath && DeleteFileW(wpath);
  free(wpath);
  return ok;
#else
  return remove(path) == 0;
#endif
}

bool bc_remove_dir(const char *dir)
{
#ifdef _WIN32
  wchar_t *wdir = bc_utf16(dir);
  const bool ok = wdir && RemoveDirectoryW(wdir);
  free(wdir);
  return ok;
#else
  return rmdir(dir) == 0;
#endif
}

bool bc_copy_permissions(const char *from, const char *to)
{
#ifdef _WIN32
  (void)from;
  (void)to;
  return true;
#else
  struct stat st;
  return stat(from, &st) == 0 && chmod(to, st.st_mode & 0777) == 0;
#endif
}

bool bc_exe_path(char *out, size_t size)
{
  char path[BC_PATH_MAX];
#ifdef _WIN32
  wchar_t wpath[32768];
  static wchar_t wlong[32768];
  const DWORD n = GetModuleFileNameW(NULL, wpath, 32768);
  if (n == 0 || n >= 32768) {
    return false;
  }
  /* Started through an 8.3 short path (MYGAME~1.EXE): use the name the folder listing shows. */
  const DWORD long_n = GetLongPathNameW(wpath, wlong, 32768);
  if (!bc_utf8(long_n > 0 && long_n < 32768 ? wlong : wpath, path, sizeof(path))) {
    return false;
  }
#elif defined(__APPLE__)
  char raw[BC_PATH_MAX];
  uint32_t raw_size = sizeof(raw);
  if (_NSGetExecutablePath(raw, &raw_size) != 0 || realpath(raw, path) == NULL) {
    return false;
  }
#else
  const ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
  if (n <= 0) {
    return false;
  }
  path[n] = '\0';
#endif
  bc_path_normalize(path);
  const int written = snprintf(out, size, "%s", path);
  return written > 0 && (size_t)written < size;
}

bool bc_exe_dir(char *out, size_t size)
{
  char path[BC_PATH_MAX];
  if (!bc_exe_path(path, sizeof(path))) {
    return false;
  }
  bc_path_dirname(out, size, path);
  return true;
}

bool bc_make_executable(const char *path)
{
#ifdef _WIN32
  (void)path;
  return true;
#else
  return chmod(path, 0755) == 0;
#endif
}

const char *bc_exe_extension(void)
{
#ifdef _WIN32
  return ".exe";
#else
  return "";
#endif
}

bool bc_path_make_absolute(char *out, size_t size, const char *path)
{
  char cwd[BC_PATH_MAX];
#ifdef _WIN32
  wchar_t wcwd[BC_PATH_MAX];
  const DWORD n = GetCurrentDirectoryW(BC_PATH_MAX, wcwd);
  if (n == 0 || n >= BC_PATH_MAX || !bc_utf8(wcwd, cwd, sizeof(cwd))) {
    return false;
  }
#else
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    return false;
  }
#endif
  bc_path_normalize(cwd);
  return bc_path_join(out, size, cwd, path);
}

bool bc_list_dir(const char *dir, BC_DirFn fn, void *user)
{
#ifdef _WIN32
  char pattern[BC_PATH_MAX];
  if (!bc_path_join(pattern, sizeof(pattern), dir, "*")) {
    return false;
  }
  wchar_t *wpattern = bc_utf16(pattern);
  WIN32_FIND_DATAW data;
  HANDLE find = wpattern ? FindFirstFileW(wpattern, &data) : INVALID_HANDLE_VALUE;
  free(wpattern);
  if (find == INVALID_HANDLE_VALUE) {
    return false;
  }
  do {
    char name[BC_PATH_MAX];
    if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0 ||
        !bc_utf8(data.cFileName, name, sizeof(name)))
    {
      continue;
    }
    const bool is_dir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                        !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    fn(user, name, is_dir);
  } while (FindNextFileW(find, &data));
  FindClose(find);
  return true;
#else
  DIR *d = opendir(dir);
  if (d == NULL) {
    return false;
  }
  struct dirent *entry;
  while ((entry = readdir(d)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    char path[BC_PATH_MAX];
    struct stat st;
    /* lstat: a symbolic link is never recursed into, which rules out cycles. */
    const bool is_dir = bc_path_join(path, sizeof(path), dir, entry->d_name) &&
                        lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
    fn(user, entry->d_name, is_dir);
  }
  closedir(d);
  return true;
#endif
}

/* -------------------------------------------------------------------------------------------- */
/* Lexical paths */

/** Length of the root prefix: "//" (UNC), "C:/" or "C:", "/", or 0 for relative paths. */
static size_t bc_path_root_length(const char *path)
{
  if (path[0] == '/' && path[1] == '/') {
    return 2;
  }
  if (isalpha((unsigned char)path[0]) && path[1] == ':') {
    return path[2] == '/' ? 3 : 2;
  }
  return path[0] == '/' ? 1 : 0;
}

void bc_path_normalize(char *path)
{
#ifdef _WIN32
  for (char *p = path; *p != '\0'; p++) {
    if (*p == '\\') {
      *p = '/';
    }
  }
#endif
  char out[BC_PATH_MAX];
  size_t segment_start[BC_PATH_MAX / 2];
  size_t depth = 0;

  const size_t root = bc_path_root_length(path);
  const bool absolute = root > 0 && path[root - 1] == '/';
  memcpy(out, path, root);
  size_t len = root;

  const char *p = path + root;
  while (*p != '\0') {
    const char *end = strchr(p, '/');
    const size_t n = end ? (size_t)(end - p) : strlen(p);
    if (n == 0 || (n == 1 && p[0] == '.')) {
      /* Empty or "." segment: nothing to emit. */
    }
    else if (n == 2 && p[0] == '.' && p[1] == '.' && depth > 0 &&
             !(len - segment_start[depth - 1] == 2 && out[segment_start[depth - 1]] == '.' &&
               out[segment_start[depth - 1] + 1] == '.'))
    {
      /* ".." cancels the previous real segment. */
      depth--;
      len = segment_start[depth];
      if (len > root) {
        len--; /* Drop the separator before the removed segment. */
      }
    }
    else if (n == 2 && p[0] == '.' && p[1] == '.' && absolute) {
      /* ".." above the root of an absolute path stays at the root. */
    }
    else {
      if (len > root) {
        out[len++] = '/';
      }
      segment_start[depth++] = len;
      memcpy(out + len, p, n);
      len += n;
    }
    p += n;
    if (*p == '/') {
      p++;
    }
  }
  if (len == 0) {
    out[len++] = '.';
  }
  out[len] = '\0';
  strcpy(path, out);
}

bool bc_path_is_absolute(const char *path)
{
#ifdef _WIN32
  if ((path[0] == '\\' && path[1] == '\\') ||
      (isalpha((unsigned char)path[0]) && path[1] == ':' && (path[2] == '/' || path[2] == '\\')))
  {
    return true;
  }
#endif
  return path[0] == '/';
}

bool bc_path_join(char *out, size_t size, const char *a, const char *b)
{
  const int n = bc_path_is_absolute(b) || a[0] == '\0' ? snprintf(out, size, "%s", b) :
                                                         snprintf(out, size, "%s/%s", a, b);
  if (n < 0 || (size_t)n >= size) {
    return false;
  }
  bc_path_normalize(out);
  return true;
}

void bc_path_dirname(char *out, size_t size, const char *path)
{
  const char *slash = strrchr(path, '/');
  if (slash == NULL) {
    snprintf(out, size, ".");
    return;
  }
  size_t n = (size_t)(slash - path);
  const size_t root = bc_path_root_length(path);
  if (n < root) {
    n = root; /* Keep "/" and "C:/". */
  }
  snprintf(out, size, "%.*s", (int)n, path);
}

const char *bc_path_basename(const char *path)
{
  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

static bool bc_path_prefix_equal(const char *a, const char *b, size_t n)
{
#ifdef _WIN32
  for (size_t i = 0; i < n; i++) {
    if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
      return false;
    }
  }
  return true;
#else
  return strncmp(a, b, n) == 0;
#endif
}

bool bc_path_relative(char *out, size_t size, const char *base_dir, const char *path)
{
  size_t n = strlen(base_dir);
  if (n > 0 && base_dir[n - 1] == '/') {
    n--; /* Root "/" or "C:/". */
  }
  if (strlen(path) < n || !bc_path_prefix_equal(base_dir, path, n)) {
    return false;
  }
  if (path[n] == '\0') {
    return snprintf(out, size, ".") < (int)size;
  }
  if (path[n] != '/') {
    return false;
  }
  const int written = snprintf(out, size, "%s", path + n + 1);
  return written >= 0 && (size_t)written < size;
}

bool bc_path_is_inside(const char *dir, const char *path)
{
  char rel[BC_PATH_MAX];
  return bc_path_relative(rel, sizeof(rel), dir, path);
}

bool bc_path_has_extension(const char *path, const char *ext)
{
  const size_t n = strlen(path);
  const size_t e = strlen(ext);
  if (n < e) {
    return false;
  }
  for (size_t i = 0; i < e; i++) {
    if (tolower((unsigned char)path[n - e + i]) != tolower((unsigned char)ext[i])) {
      return false;
    }
  }
  return true;
}
