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
 * digest = BLAKE2b-256(BC_NATIVE_CONTEXT || for each covered file, in walk order:
 *                      relative path (UTF-8, '/' separators) || 0x00 || BLAKE2b-256(contents))
 * Walk order: depth first, the entries of each folder sorted bytewise by name. Symbolic links to
 * folders and reparse points are not followed (bc_list_dir); links to files are hashed through. */

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

/** Remove every Python bytecode file under \a root (after the player exits). */
bool bc_remove_bytecode(const char *root, BC_NativeScan *r_scan);

#ifdef __cplusplus
}
#endif

#endif /* BC_NATIVE_H */
