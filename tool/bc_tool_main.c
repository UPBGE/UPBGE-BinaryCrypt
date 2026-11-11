/* SPDX-License-Identifier: GPL-2.0-or-later */

/* bc_tool entry point: GUI by default, headless batch for scripts and CI. */

#include <stdio.h>
#include <string.h>

#include "bc_job.h"
#include "bc_key.h"
#include "bc_project.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

#include "bc_gui.h"

static void bc_usage(FILE *f)
{
  fputs("UPBGE BinaryCrypt tool: encrypts the .blend files, Python modules and data files of a UPBGE\n"
        "game for its player.\n"
        "\n"
        "usage:\n"
#ifdef BC_WITH_GUI
        "  bc_tool [project.bcproj]         open the editor (optionally with a project)\n"
#endif
        "  bc_tool --batch project.bcproj   encrypt a project without a window\n"
        "  bc_tool --fingerprint            print the fingerprint of this build's key\n"
        "  bc_tool --export-key file        save this build's key, to rebuild later with the\n"
        "                                   same key (CMake option BINARYCRYPT_KEY_FILE)\n"
        "  bc_tool --help\n",
        f);
}

static void bc_cli_log(void *user, BC_LogLevel level, const char *message)
{
  (void)user;
  if (level == BC_LOG_INFO) {
    printf("%s\n", message);
    fflush(stdout);
  }
  else {
    fprintf(stderr, "%s: %s\n", level == BC_LOG_ERROR ? "error" : "warning", message);
  }
}

void bc_tool_launcher_path(char *out, size_t size)
{
  char dir[BC_PATH_MAX];
  out[0] = '\0';
  if (bc_exe_dir(dir, sizeof(dir))) {
    char name[64];
    snprintf(name, sizeof(name), "bc_launcher%s", bc_exe_extension());
    bc_path_join(out, size, dir, name);
  }
}

static int bc_run_batch(const char *project_path)
{
  BC_Project project;
  char err[BC_PATH_MAX + 128];
  bc_project_init(&project);
  if (!bc_project_load(&project, project_path, err, sizeof(err))) {
    fprintf(stderr, "error: %s: %s\n", project_path, err);
    return 1;
  }
  char launcher[BC_PATH_MAX];
  bc_tool_launcher_path(launcher, sizeof(launcher));
  const double start = bc_time_seconds();
  BC_Job *job = bc_job_create(&project, bc_build_key(), launcher, bc_cli_log, NULL);
  bc_project_free(&project);
  if (job == NULL) {
    return 1;
  }
  int result;
  while ((result = bc_job_step(job, 1.0)) == 1) {
  }
  bc_job_destroy(job);
  if (result == 0) {
    printf("Done in %.2f s\n", bc_time_seconds() - start);
  }
  return result == 0 ? 0 : 1;
}

static int bc_export_key(const char *path)
{
  if (bc_is_file(path) || bc_is_dir(path)) {
    fprintf(stderr, "error: '%s' already exists, refusing to overwrite it\n", path);
    return 1;
  }
  char hex[BC_KEY_HEX_SIZE + 1];
  bc_key_to_hex(bc_build_key(), hex);
  FILE *f = bc_fopen(path, "wb");
  const bool ok = f != NULL && fprintf(f, "%s\n", hex) > 0;
  crypto_wipe(hex, sizeof(hex));
  if (f == NULL || fclose(f) != 0 || !ok) {
    fprintf(stderr, "error: cannot write '%s'\n", path);
    return 1;
  }
  char fingerprint[BC_FINGERPRINT_SIZE];
  bc_key_fingerprint(bc_build_key(), fingerprint);
  printf("Key %s saved to '%s'.\n"
         "Keep it private: anyone holding it can decrypt the games encrypted with it.\n",
         fingerprint,
         path);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc == 3 && strcmp(argv[1], "--batch") == 0) {
    return bc_run_batch(argv[2]);
  }
  if (argc == 3 && strcmp(argv[1], "--export-key") == 0) {
    return bc_export_key(argv[2]);
  }
  if (argc == 2 && strcmp(argv[1], "--fingerprint") == 0) {
    char fingerprint[BC_FINGERPRINT_SIZE];
    bc_key_fingerprint(bc_build_key(), fingerprint);
    printf("%s\n", fingerprint);
    return 0;
  }
  if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
    bc_usage(stdout);
    return 0;
  }
#ifdef BC_WITH_GUI
  if (argc == 1 || (argc == 2 && argv[1][0] != '-')) {
#  ifdef _WIN32
    /* Console program so the batch mode can print. Started from Explorer, Windows 11 24H2 and
     * later give it no console (bc_tool.manifest); older Windows give it one of its own, released
     * here so only the editor window remains (it still shows for a moment). */
    DWORD processes[2];
    if (GetConsoleProcessList(processes, 2) == 1) {
      FreeConsole();
    }
#  endif
    return bc_gui_run(argc == 2 ? argv[1] : NULL);
  }
#endif
  bc_usage(stderr);
  return 2;
}
