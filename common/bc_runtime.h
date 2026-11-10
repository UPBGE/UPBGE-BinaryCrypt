/* SPDX-License-Identifier: GPL-2.0-or-later */

/* UPBGE runtime copy: the player and what it loads, from a UPBGE folder (a release, or the bin
 * folder of a build) into the game folder's engine/, at every export.
 *
 * Only what the player needs is taken, by name (BC_RUNTIME_CONTENTS): never the editor, the build
 * tools, the batch files, debug symbols (.pdb) or Python bytecode (the Python integrity level would
 * remove it from the game folder after every copy, and the next export would copy it again).
 *
 * Incremental. A record in engine/ (BC_RUNTIME_RECORD) keeps the size and time of the source of
 * every copied file:
 * - a file whose source matches its record, and whose copy exists, is not copied again:
 *   re-exporting an unchanged runtime costs two stat calls per file and no reads;
 * - the copy is not compared: one changed on purpose (branded, signed) stays until its source
 *   changes. Deleting a copy brings the original back at the next export;
 * - a recorded file the UPBGE folder no longer has (a version folder renamed by an update, a
 *   library dropped) is removed, with the folders it leaves empty;
 * - anything else in engine/ is never touched: it is not in the record.
 * A file is copied into a temporary name and renamed over the old copy: an export stopped half way
 * never leaves a truncated file under a recorded name, and on POSIX a running game keeps the old
 * file mapped instead of crashing on a library truncated under it.
 *
 * Time sliced like the rest of the export (bc_job.h): bc_runtime_step does one unit of work, at most
 * one buffer of one file. Two allocations hold every path: one arena for the listing, one buffer
 * for the record, parsed in place. */

#ifndef BC_RUNTIME_H
#define BC_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bc_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Folder of the copied runtime inside the game folder, and its record. */
#define BC_RUNTIME_DIR "engine"
#define BC_RUNTIME_RECORD ".bc_runtime"

/** The player, relative to the UPBGE folder and to BC_RUNTIME_DIR; and what is copied. */
#if defined(_WIN32)
#  define BC_RUNTIME_PLAYER "blenderplayer.exe"
#  define BC_RUNTIME_CONTENTS "blenderplayer.exe, the .dll files, the version (5.x), blender.crt, blender.shared and license folders and copyright.txt"
#elif defined(__APPLE__)
#  define BC_RUNTIME_PLAYER "Blenderplayer.app/Contents/MacOS/Blenderplayer"
#  define BC_RUNTIME_CONTENTS "Blenderplayer.app"
#else
#  define BC_RUNTIME_PLAYER "blenderplayer"
#  define BC_RUNTIME_CONTENTS "blenderplayer, the version (5.x), lib and license folders and copyright.txt"
#endif

typedef struct BC_RuntimeFile {
  /** Relative to both folders, '/' separated; points into BC_RuntimeCopy::names. */
  const char *path;
  /** Of the source (bc_file_stat). */
  uint64_t size, mtime;
  /** Copied by this run. */
  bool copy;
} BC_RuntimeFile;

typedef struct BC_RuntimeCopy {
  char from[BC_PATH_MAX];
  char to[BC_PATH_MAX];
  /** The UPBGE folder's files, sorted by path. */
  BC_RuntimeFile *files;
  int file_count, file_capacity;
  char *names;
  size_t names_size, names_capacity;
  /** Recorded files the UPBGE folder no longer has; the paths point into #record. */
  const char **stale;
  int stale_count;
  char *record;

  /* Progress. */
  int stale_next;
  int next;
  FILE *in, *out;
  /** Folder of the last copy, already created: consecutive files mostly share it. */
  char made[BC_PATH_MAX];
  /** Bytes to copy in this run, and copied so far. */
  uint64_t copy_bytes, done_bytes;
  int copy_count, copied, removed;
  /** Entries skipped: links to folders. */
  int skipped;
  /** The record exists but cannot be read: everything is copied, nothing removed. */
  bool record_bad;
  /** The record no longer matches engine/: written by bc_runtime_save. */
  bool dirty;
} BC_RuntimeCopy;

/**
 * List what \a upbge_dir gives and compare it with the record of \a engine_dir. Reads only:
 * nothing is written before bc_runtime_step. \return false, with the reason in \a err, when the
 * folder has no player or cannot be read.
 */
bool bc_runtime_begin(BC_RuntimeCopy *c, const char *upbge_dir, const char *engine_dir, char *err, size_t err_size);

/** One unit of work with \a buffer: remove a file gone from the UPBGE folder, or copy one buffer.
 * \return 1 while work remains, 0 when done, -1 on failure (\a err; the partial copy is removed). */
int bc_runtime_step(BC_RuntimeCopy *c, uint8_t *buffer, size_t buffer_size, char *err, size_t err_size);

/** File being copied, relative to engine/, NULL between files. */
const char *bc_runtime_current(const BC_RuntimeCopy *c);

/** True when the copy writes engine/\a path. */
bool bc_runtime_has(const BC_RuntimeCopy *c, const char *path);

/** Write the record once the copy is done, when it changed. */
bool bc_runtime_save(BC_RuntimeCopy *c, char *err, size_t err_size);

/** Free; an unfinished copy loses its partial file. */
void bc_runtime_end(BC_RuntimeCopy *c);

#ifdef __cplusplus
}
#endif

#endif /* BC_RUNTIME_H */
