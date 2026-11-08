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
  uint64_t size;
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

/** The files an export of \a p encrypts: the listed files, and what the listed folders give
 * (.blend files, Python modules, files with one of the \a data_ext extensions; hidden folders, the
 * output folder and already encrypted files left out), sorted, each once. Problems go to \a log
 * (may be NULL). \return false when an input is missing, outside the source folder or inside the
 * output folder, or a file cannot be read; \a r_list is then empty. One code path for the export
 * and for what the editor shows. */
bool bc_project_list_files(const BC_Project *p,
                           char (*data_ext)[BC_DATA_EXT_SIZE],
                           int data_ext_count,
                           BC_LogFn log,
                           void *user,
                           BC_FileList *r_list);

void bc_file_list_free(BC_FileList *list);

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
