/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Batch job: encrypts every file of a project, then writes the game executable (the launcher with
 * the manifest appended, see bc_embed.h).
 *
 * Time sliced instead of threaded: #bc_job_step does about `budget` seconds of work and returns.
 * The GUI calls it once per frame and stays responsive with a live progress bar and no
 * synchronization at all; headless mode calls it with an unbounded budget. One code path. */

#ifndef BC_JOB_H
#define BC_JOB_H

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
