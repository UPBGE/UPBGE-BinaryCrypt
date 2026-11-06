/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Thin OS layer shared by the tool and the launcher.
 *
 * Every path is UTF-8 and uses '/' as separator internally (Windows APIs accept it). On Windows
 * paths are converted to UTF-16 only at the system call boundary, so non-ASCII file names work. */

#ifndef BC_PLATFORM_H
#define BC_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BC_PATH_MAX 4096

/** Cryptographically secure random bytes from the operating system. */
bool bc_random_bytes(void *dst, size_t size);

/** Monotonic clock in seconds, for time budgets only. */
double bc_time_seconds(void);

FILE *bc_fopen(const char *path, const char *mode);
bool bc_file_size(const char *path, uint64_t *r_size);
bool bc_is_file(const char *path);
bool bc_is_dir(const char *path);
/** Create \a dir and any missing parent. */
bool bc_mkdir_p(const char *dir);
/** Atomically replace \a to with \a from (same volume). */
bool bc_rename_replace(const char *from, const char *to);
bool bc_remove(const char *path);
/** Full path of the running executable, and the directory containing it. */
bool bc_exe_path(char *out, size_t size);
bool bc_exe_dir(char *out, size_t size);
/** Give \a path execute permission (POSIX 0755); nothing to do on Windows. */
bool bc_make_executable(const char *path);
/** Extension of executables on this platform: ".exe" on Windows, "" elsewhere. */
const char *bc_exe_extension(void);
/** \a path made absolute against the current directory, normalized. */
bool bc_path_make_absolute(char *out, size_t size, const char *path);

/** Called for every entry of a directory except "." and "..". Symbolic links and reparse points
 * to directories are reported as files (is_dir false) so recursion can never loop. */
typedef void (*BC_DirFn)(void *user, const char *name, bool is_dir);
bool bc_list_dir(const char *dir, BC_DirFn fn, void *user);

/* -------------------------------------------------------------------------------------------- */
/* Lexical path helpers: pure string operations, no file system access. */

/** '\\' to '/' (Windows), collapse "//", "." and "..", strip a trailing '/' except at the root. */
void bc_path_normalize(char *path);
bool bc_path_is_absolute(const char *path);
/** \a b if it is absolute, otherwise \a a + "/" + \a b, normalized. */
bool bc_path_join(char *out, size_t size, const char *a, const char *b);
void bc_path_dirname(char *out, size_t size, const char *path);
const char *bc_path_basename(const char *path);
/** Path of \a path relative to \a base_dir, only when it lies inside it ("." when equal). Both
 * must be normalized absolute paths. Case-insensitive on Windows. */
bool bc_path_relative(char *out, size_t size, const char *base_dir, const char *path);
/** True when \a path is \a dir or lies inside it. */
bool bc_path_is_inside(const char *dir, const char *path);
/** Case-insensitive (ASCII) extension check, \a ext includes the dot. */
bool bc_path_has_extension(const char *path, const char *ext);

#ifdef _WIN32
#  include <wchar.h>
/** UTF-8 to a newly allocated UTF-16 string (free()), NULL on failure. */
wchar_t *bc_utf16(const char *utf8);
bool bc_utf8(const wchar_t *utf16, char *out, size_t size);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BC_PLATFORM_H */
