/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Batch job: encrypts every file of a project, then writes the game executable (the launcher with
 * the manifest appended, see bc_embed.h).
 *
 * Time sliced instead of threaded: #bc_job_step does about `budget` seconds of work and returns.
 * The GUI calls it once per frame and stays responsive with a live progress bar and no
 * synchronization at all; headless mode calls it with an unbounded budget. One code path. */

#ifndef BC_JOB_H
#define BC_JOB_H

#include <stdbool.h>
#include <stdint.h>

#include "bc_keyring.h"
#include "bc_project.h"
#include "binarycrypt_format.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum BC_LogLevel {
  BC_LOG_INFO,
  BC_LOG_WARNING,
  BC_LOG_ERROR,
} BC_LogLevel;

typedef void (*BC_LogFn)(void *user, BC_LogLevel level, const char *message);

typedef struct BC_Job BC_Job;

/** One file a project gives. */
typedef struct BC_ListedFile {
  char *path;
  /** Size and modification time (bc_file_stat), from the one stat call of the listing. */
  uint64_t size, mtime;
  /** BC_KIND_*: .blend, .py, anything else a data file. */
  uint8_t kind;
} BC_ListedFile;

typedef struct BC_FileList {
  BC_ListedFile *files;
  int count;
  int capacity;
  /** Already encrypted files found in folders and left out (most likely old outputs). */
  int skipped;
} BC_FileList;

/** Every file a listing meets, given to the export or not: the listed files and all the files of
 * the scanned folders (the editor counts their types). */
typedef void (*BC_SeenFn)(void *user, const char *path);

/** The files an export of \a p encrypts: the listed files, and what the listed folders give
 * (.blend files, Python modules, files with one of the \a data_ext extensions; hidden folders, the
 * output folder and already encrypted files left out), sorted, each once. Problems go to \a log,
 * every file met to \a seen (both may be NULL). \return false when an input is missing, outside
 * the source folder or inside the output folder, or a file cannot be read; \a r_list is then
 * empty. One code path for the export and for what the editor shows. */
bool bc_project_list_files(const BC_Project *p,
                           char (*data_ext)[BC_DATA_EXT_SIZE],
                           int data_ext_count,
                           BC_LogFn log,
                           BC_SeenFn seen,
                           void *user,
                           BC_FileList *r_list);

void bc_file_list_free(BC_FileList *list);

/** Listed files of \a list whose size or modification time differ from their record in
 * \a records (sorted by path, as BC_KeyRing keeps them), or that have none: what changed since the
 * export that wrote the records, known without reading a file. A touched but unchanged file
 * counts; the export itself tells them apart by hash. Empty files are copied, never recorded, and
 * not counted. */
int bc_file_list_changed(const BC_Project *p, const BC_FileList *list, const BC_KeyRecord *records, int record_count);

/** Online key with a store's provider (bc_project_key_store): what it still needs, as warnings to
 * \a log. An export goes ahead without them (a provider of your own may differ): the store
 * library missing next to the provider, for Steam a steam_appid.txt that would ship, for itch.io
 * no .itch.toml asking the itch app for the player's login, for Meta a key kept after the first
 * launch (no entitlement check at later launches) or a tool that cannot make Windows games.
 * \return how many. */
int bc_project_store_notes(const BC_Project *p, BC_LogFn log, void *user);

/** Validate \a p and list every file to encrypt. Returns NULL when the project is not runnable;
 * every problem is reported through \a log. The project is copied, it may change afterwards.
 * \a launcher_path: the bc_launcher built together with the caller (same key). */
BC_Job *bc_job_create(const BC_Project *p,
                      const uint8_t key[BC_KEY_SIZE],
                      const char *launcher_path,
                      BC_LogFn log,
                      void *user);

/** Work for about \a budget_seconds. \return 1 while work remains, 0 when every file is
 * encrypted and the game executable written, -1 on failure (reported through the log). */
int bc_job_step(BC_Job *job, double budget_seconds);

/** Fraction of the work done, 0..1. */
double bc_job_progress(const BC_Job *job);
/** Source file being processed, or a short status. */
const char *bc_job_status(const BC_Job *job);

/** Abort if unfinished (removes the partial output) and free. */
void bc_job_destroy(BC_Job *job);

#ifdef __cplusplus
}
#endif

#endif /* BC_JOB_H */
