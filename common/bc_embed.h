/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Game executable and where its manifest lives.
 *
 * Embedded (default): the launcher with the manifest appended, so a shipped game is one
 * executable (named after the game), the encrypted .blend files and the engine/ folder.
 * External: a byte-identical copy of the launcher plus BC_MANIFEST_FILENAME next to it. A
 * launcher signed once keeps a valid signature in every export, and tools that rewrite or sign
 * executables (strip, UPX, macOS codesign) only ever see a plain launcher.
 *
 * Embedded layout:
 *   [ launcher executable ][ manifest ][ zero padding ][ trailer: 16 bytes ]
 *   trailer = u32le manifest size, u32le padding size, "UPBGEBCX"
 *
 * Executables ignore data past their image, so the launcher runs unchanged. The padding makes the
 * total size a multiple of 8: Authenticode places the signature table at the end of the file on
 * an 8 byte boundary, so signing the finished executable (signtool, osslsigncode) appends the
 * table right after the trailer, and the reader finds the trailer just before it. Anything that
 * rewrites the file from its headers (strip, upx...) drops the manifest: run such tools on the
 * launcher before exporting, never on the exported game executable. */

#ifndef BC_EMBED_H
#define BC_EMBED_H

#include <stdbool.h>
#include <stddef.h>

#include "bc_manifest.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_EMBED_MAGIC "UPBGEBCX"
#define BC_EMBED_TRAILER_SIZE 16
#define BC_EMBED_ALIGNMENT 8

/** Copy \a launcher_path to \a out_path (atomic, executable permission), with \a m appended, or
 * byte-identical when \a m is NULL (external manifest). */
bool bc_embed_write(const char *launcher_path,
                    const char *out_path,
                    const BC_Manifest *m,
                    const uint8_t key[BC_KEY_SIZE],
                    char *err,
                    size_t err_size);

/** Read and authenticate the manifest appended to \a exe_path (BC_MANIFEST_MISSING if none). */
BC_ManifestResult bc_embed_read(const char *exe_path,
                                const uint8_t key[BC_KEY_SIZE],
                                BC_Manifest *r_manifest);

/** True for a PE executable carrying an Authenticode signature table. */
bool bc_exe_has_signature(const char *path);

/** External manifest file (atomic write). Reading returns BC_MANIFEST_MISSING if absent. */
bool bc_manifest_file_write(const char *path,
                            const BC_Manifest *m,
                            const uint8_t key[BC_KEY_SIZE],
                            char *err,
                            size_t err_size);
BC_ManifestResult bc_manifest_file_read(const char *path,
                                        const uint8_t key[BC_KEY_SIZE],
                                        BC_Manifest *r_manifest);

#ifdef __cplusplus
}
#endif

#endif /* BC_EMBED_H */
