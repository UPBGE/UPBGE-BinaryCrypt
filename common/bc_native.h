/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Code digest of a game folder: native code, and optionally Python.
 *
 * The launcher hashes the player before handing it the keys, but the player loads other code from
 * the game folder: its DLLs and shared libraries (found first in the executable's own folder),
 * Python extension modules, Python modules. Replacing one, or adding one under a name the loader
 * looks for (a proxy version.dll, a .pth or sitecustomize.py in site-packages), runs code inside
 * the player with the keys in memory. The digest covers every such file of the folder, so a
 * changed, added or removed one is refused at launch.
 *
 * Native code = names ending in .exe, .dll, .pyd, .so, .dylib, or a versioned .so.N[.N...].
 * Python (optional) = .py, .pyw, .pth and .zip (the default sys.path names a python3XX.zip before
 * the standard library). ASCII case-insensitive.
 *
 * Python bytecode (.pyc, .pyo) cannot be hashed: the player writes .pyc files next to the modules
 * it imports, and a hash of .py alone is pointless while a .pyc that claims the source's time and
 * size is loaded without reading the source. So the Python level removes every bytecode file
 * instead: at export, before each launch and after the player exits. In a folder the player
 * cannot write (Program Files, /opt) none can appear, because the export left none; one that
 * cannot be removed was put there by someone else, and the launch is refused.
 *
 * digest = BLAKE3 in key derivation mode, context BC_NATIVE_CONTEXT, over: for each covered file,
 *          in walk order, relative path (UTF-8, '/' separators) || 0x00 || BLAKE3-256(contents)
 * Walk order: depth first, the entries of each folder sorted bytewise by name. Symbolic links to
 * folders and reparse points are not followed (bc_list_dir); links to files are hashed through.
 *
 * The digest input itself, the records, is what the export also saves as BC_NATIVE_RECORD in the
 * player's folder. A launcher whose digest differs reads it, trusts it only when it hashes to the
 * manifest's digest, and compares: which file was changed, added or removed (bc_native_compare).
 * The success path never reads it. */

#ifndef BC_NATIVE_H
#define BC_NATIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bc_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_NATIVE_CONTEXT "UPBGE-BinaryCrypt native code v1"
#define BC_NATIVE_DIGEST_SIZE 32
/** The records of the export, in the player's folder. No code extension: never covered itself. */
#define BC_NATIVE_RECORD ".bc_code"
/** Largest record file a launcher reads: far above any game (about 100 bytes a file). */
#define BC_NATIVE_RECORD_MAX (64u << 20)

/** True when \a name (a file name, not a path) is native code by the rule above. */
bool bc_is_native_code(const char *name);
/** True for the Python files of the Python level: .py, .pyw, .pth, .zip. */
bool bc_is_python_source(const char *name);
/** True for Python bytecode: .pyc, .pyo. */
bool bc_is_python_bytecode(const char *name);

typedef struct BC_NativeScan {
  /** Files hashed, and their bytes. */
  int files;
  uint64_t bytes;
  /** Bytecode files removed. */
  int bytecode_removed;
  /** A bytecode file that could not be removed, or empty. */
  char locked[BC_PATH_MAX];
} BC_NativeScan;

/** Digest of the code under \a root, leaving out the files whose paths relative to \a root are
 * listed in \a skip (the game executable, which carries the manifest, and the player, which has
 * its own hash). With \a python, also covers Python files and removes Python bytecode on the way.
 * \a r_scan (optional) receives what was done. \return false when a folder or file could not be
 * read, or a bytecode file could not be removed (r_scan->locked names it). */
bool bc_native_digest(const char *root,
                      const char *const *skip,
                      int skip_count,
                      bool python,
                      uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                      BC_NativeScan *r_scan);

/** Files bc_native_digest_held hashed and keeps open. Windows: shared for reading only, so nobody
 * can write, replace or delete them until they are released; the player loads exactly the code
 * that was checked, even a module it imports long after the start. Elsewhere it stays empty: a
 * file can be renamed over while open, so holding it would prove nothing. */
typedef struct BC_NativeHold {
  void **handles;
  int count;
  int capacity;
} BC_NativeHold;

/** bc_native_digest that also hands back its input, the records (see above), for BC_NATIVE_RECORD
 * or for bc_native_compare. *r_records is malloc'ed (free it), NULL on failure. */
bool bc_native_digest_records(const char *root,
                              const char *const *skip,
                              int skip_count,
                              bool python,
                              uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                              BC_NativeScan *r_scan,
                              uint8_t **r_records,
                              size_t *r_records_size);

/** The digest of \a records: equal to the manifest's, they are the export's own. */
void bc_native_records_digest(const uint8_t *records, size_t size, uint8_t r_digest[BC_NATIVE_DIGEST_SIZE]);

/** Each file that differs between the export's records (\a reference) and the game folder's now
 * (\a current), by path: \a fn gets "changed", "added" or "removed". \return how many, -1 when a
 * record list is malformed or memory runs out. */
int bc_native_compare(const uint8_t *reference,
                      size_t reference_size,
                      const uint8_t *current,
                      size_t current_size,
                      void (*fn)(void *user, const char *change, const char *path),
                      void *user);

/** bc_native_digest that keeps every hashed file open in \a hold (released by bc_native_release,
 * also on failure). */
bool bc_native_digest_held(const char *root,
                           const char *const *skip,
                           int skip_count,
                           bool python,
                           uint8_t r_digest[BC_NATIVE_DIGEST_SIZE],
                           BC_NativeScan *r_scan,
                           BC_NativeHold *hold);

void bc_native_release(BC_NativeHold *hold);

/** Remove every Python bytecode file under \a root (after the player exits). */
bool bc_remove_bytecode(const char *root, BC_NativeScan *r_scan);

#ifdef __cplusplus
}
#endif

#endif /* BC_NATIVE_H */
