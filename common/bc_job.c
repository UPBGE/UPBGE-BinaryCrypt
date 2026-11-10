/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_job.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "bc_brand.h"
#include "bc_compress.h"
#include "bc_embed.h"
#include "bc_key.h"
#include "bc_keyring.h"
#include "bc_native.h"
#include "bc_runtime.h"
#include "bc_seal.h"
#include "blake3.h"

#define BC_HASH_READ_SIZE (1 << 20)

typedef enum BC_JobPhase {
  BC_PHASE_COPY_RUNTIME,
  BC_PHASE_BRAND_PLAYER,
  BC_PHASE_HASH_PLAYER,
  BC_PHASE_SEAL,
  BC_PHASE_GAME_EXE,
  BC_PHASE_DONE,
  BC_PHASE_FAILED,
} BC_JobPhase;

typedef struct BC_JobFile {
  char *in;
  char *out;
  uint64_t size, mtime;
  /** Hash of the source: its container's source id (bc_seal.h), and tells changed files from
   * unchanged ones. Also the plaintext hash when the file is sealed as it is. */
  uint8_t hash[BC_PLAIN_HASH_SIZE];
  bool hashed;
  /** BC_KIND_*: .blend, .py, anything else a data file. */
  uint8_t kind;
  /** A .blend Blender did not compress: compressed before sealing (bc_compress.h). */
  bool compress;
  /** An empty module or data file (an empty __init__.py): written as it is, since a container
   * cannot be empty and there is nothing to hide. Neither hashed nor sealed, it uses no key. */
  bool copy;
  /** Key ring index of the key sealing this file, -1 for the build key. */
  int key;
} BC_JobFile;

struct BC_Job {
  /** Build key: authenticates the manifest (and masks a project key); seals the files only in
   * build key mode. */
  const uint8_t *key;
  /* Project or online key: the key file's keys. With a key per update (online only), files whose
   * plaintext is unchanged since their record keep their earlier key (and stay byte for byte
   * identical), the others get the key of this update. */
  bool key_file_keys;
  bool rotation;
  /** What the game executable checks before every launch (bc_native.h). */
  BC_Integrity integrity;
  BC_KeyRing ring;
  BC_KeyRecord *old_records; /* As loaded: sorted by path, for bsearch. */
  int old_record_count;
  int current_key;
  /** A key per update whose key an earlier export created: changed files get a key in use. */
  bool key_reused;
  char key_file[BC_PATH_MAX];
  bool key_file_single;
  int changed_files;
  int unchanged_files;
  /** Outputs already up to date: not encrypted nor written again. */
  int kept_files;
  FILE *file_hash_in;
  crypto_blake2b_ctx file_hash_ctx;
  uint16_t key_flags;
  char provider_rel[BC_PATH_MAX];
  char key_url[BC_PROJECT_URL_MAX];
  BC_LogFn log;
  void *log_user;
  BC_JobPhase phase;

  char dist_root[BC_PATH_MAX];
  char launcher_path[BC_PATH_MAX];
  char game_exe[BC_PATH_MAX];
  BC_ManifestMode manifest_mode;
  char manifest_file[BC_PATH_MAX];
  char player_rel[BC_PATH_MAX];
  char player_abs[BC_PATH_MAX];
  char main_out_rel[BC_PATH_MAX];
  /** A UPBGE folder: the runtime is copied into engine/ first, the player with it. */
  bool runtime_on;
  BC_RuntimeCopy runtime;
  /** Folders also give Python modules and the data files of these extensions. */
  char data_ext[BC_DATA_EXT_MAX][BC_DATA_EXT_SIZE];
  int data_ext_count;

  BC_JobFile *files;
  int file_count;

  int current;
  bool compressing;
  BC_Compressor compressor;
  /** The compressed copy being sealed, next to the output; removed once sealed. Empty: none. */
  char compressed[BC_PATH_MAX];
  bool sealing;
  BC_Sealer sealer;
  uint64_t current_base;

  FILE *player_file;
  blake3_hasher hash_ctx;
  uint8_t *hash_buffer;
  uint8_t player_hash[BC_PLAYER_HASH_SIZE];

  /* Windows branding (bc_brand.h); strings copied so the project may change while running. */
  bool branding;
  BC_Branding brand;
  uint8_t *ico;
  char brand_product[BC_GAME_NAME_MAX];
  char brand_company[BC_PROJECT_TEXT_MAX];
  char brand_copyright[BC_PROJECT_TEXT_MAX];

  uint64_t total_bytes;
  uint64_t done_bytes;
  char status[BC_PATH_MAX];
};

static void bc_log(BC_Job *job, const BC_LogLevel level, const char *format, ...)
{
  char message[BC_PATH_MAX + 256];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  if (job->log) {
    job->log(job->log_user, level, message);
  }
}

static const char *bc_display(const BC_Job *job, const char *path)
{
  /* Paths below the distribution root are shown relative to it: shorter, and what ends up in
   * the shipped game. Others are shown as they are. */
  const size_t n = strlen(job->dist_root);
  if (n > 0 && strncmp(path, job->dist_root, n) == 0 && path[n] == '/') {
    return path + n + 1;
  }
  return path;
}

/* -------------------------------------------------------------------------------------------- */
/* File list */

typedef struct BC_ListRules {
  char (*data_ext)[BC_DATA_EXT_SIZE];
  int data_ext_count;
  const char *skip_dir;
  BC_LogFn log;
  BC_SeenFn seen;
  void *user;
} BC_ListRules;

static void bc_list_log(const BC_ListRules *rules, const BC_LogLevel level, const char *format, ...)
{
  if (rules->log == NULL) {
    return;
  }
  char message[BC_PATH_MAX + 256];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  rules->log(rules->user, level, message);
}

static bool bc_list_add(BC_FileList *list, const char *path)
{
  if (list->count == list->capacity) {
    const int capacity = list->capacity ? list->capacity * 2 : 64;
    BC_ListedFile *files = (BC_ListedFile *)realloc(list->files, sizeof(BC_ListedFile) * (size_t)capacity);
    if (files == NULL) {
      return false;
    }
    list->files = files;
    list->capacity = capacity;
  }
  BC_ListedFile *file = &list->files[list->count];
  memset(file, 0, sizeof(*file));
  file->path = (char *)malloc(strlen(path) + 1);
  if (file->path == NULL) {
    return false;
  }
  strcpy(file->path, path);
  list->count++;
  return true;
}

typedef struct BC_ScanContext {
  BC_FileList *list;
  const BC_ListRules *rules;
  const char *dir;
  bool ok;
} BC_ScanContext;

static void bc_scan_dir(BC_FileList *list, const BC_ListRules *rules, const char *dir, bool *ok);

/** What a folder gives: .blend files, Python modules and data files. */
static bool bc_list_scans(const BC_ListRules *rules, const char *name)
{
  if (bc_path_has_extension(name, ".blend") || bc_path_has_extension(name, ".py")) {
    return true;
  }
  for (int i = 0; i < rules->data_ext_count; i++) {
    if (bc_path_has_extension(name, rules->data_ext[i])) {
      return true;
    }
  }
  return false;
}

static void bc_scan_entry(void *user, const char *name, bool is_dir)
{
  BC_ScanContext *ctx = (BC_ScanContext *)user;
  char path[BC_PATH_MAX];
  if (!ctx->ok || !bc_path_join(path, sizeof(path), ctx->dir, name)) {
    return;
  }
  if (is_dir) {
    /* Hidden folders (.git, .svn...) never hold game data. The output folder may live inside
     * the source tree and must not be encrypted again. */
    if (name[0] != '.' && strcmp(path, ctx->rules->skip_dir) != 0) {
      bc_scan_dir(ctx->list, ctx->rules, path, &ctx->ok);
    }
  }
  else if (ctx->rules->seen != NULL) {
    ctx->rules->seen(ctx->rules->user, path);
  }
  if (!is_dir && bc_list_scans(ctx->rules, name)) {
    /* Found by scanning, not listed: an encrypted file is most likely an old output (for example
     * from an earlier output folder inside the sources). Skip it instead of failing the whole
     * batch. Explicitly listed files still fail loudly in bc_seal_begin. */
    if (bc_file_is_container(path)) {
      ctx->list->skipped++;
      bc_list_log(ctx->rules, BC_LOG_WARNING, "Skipped '%s': already encrypted", path);
    }
    else {
      ctx->ok = bc_list_add(ctx->list, path);
    }
  }
}

static void bc_scan_dir(BC_FileList *list, const BC_ListRules *rules, const char *dir, bool *ok)
{
  BC_ScanContext ctx = {list, rules, dir, true};
  if (!bc_list_dir(dir, bc_scan_entry, &ctx)) {
    bc_list_log(rules, BC_LOG_WARNING, "Cannot list folder '%s'", dir);
  }
  *ok = *ok && ctx.ok;
}

static int bc_compare_listed(const void *a, const void *b)
{
  return strcmp(((const BC_ListedFile *)a)->path, ((const BC_ListedFile *)b)->path);
}

void bc_file_list_free(BC_FileList *list)
{
  for (int i = 0; i < list->count; i++) {
    free(list->files[i].path);
  }
  free(list->files);
  memset(list, 0, sizeof(*list));
}

static bool bc_list_fail(BC_FileList *list)
{
  bc_file_list_free(list);
  return false;
}

bool bc_project_list_files(const BC_Project *p,
                           char (*data_ext)[BC_DATA_EXT_SIZE],
                           const int data_ext_count,
                           BC_LogFn log,
                           BC_SeenFn seen,
                           void *user,
                           BC_FileList *r_list)
{
  memset(r_list, 0, sizeof(*r_list));
  const BC_ListRules rules = {data_ext, data_ext_count, p->output_dir, log, seen, user};
  /* Expand folders, then sort and drop duplicates (a file can be listed and also be found inside
   * a listed folder). */
  bool ok = true;
  for (int i = 0; ok && i < p->input_count; i++) {
    const char *input = p->inputs[i];
    if (!bc_path_is_inside(p->source_root, input)) {
      bc_list_log(&rules, BC_LOG_ERROR, "'%s' is outside the source folder", input);
      return bc_list_fail(r_list);
    }
    if (bc_path_is_inside(p->output_dir, input)) {
      bc_list_log(&rules, BC_LOG_ERROR, "'%s' is inside the output folder", input);
      return bc_list_fail(r_list);
    }
    if (bc_is_dir(input)) {
      bc_scan_dir(r_list, &rules, input, &ok);
    }
    else if (bc_is_file(input)) {
      if (seen != NULL) {
        seen(user, input);
      }
      ok = bc_list_add(r_list, input);
    }
    else {
      bc_list_log(&rules, BC_LOG_ERROR, "Input '%s' does not exist", input);
      return bc_list_fail(r_list);
    }
  }
  if (!ok) {
    bc_list_log(&rules, BC_LOG_ERROR, "Out of memory while listing the input files");
    return bc_list_fail(r_list);
  }
  if (r_list->count > 0) {
    qsort(r_list->files, (size_t)r_list->count, sizeof(BC_ListedFile), bc_compare_listed);
  }
  int unique = 0;
  for (int i = 0; i < r_list->count; i++) {
    if (unique > 0 && strcmp(r_list->files[unique - 1].path, r_list->files[i].path) == 0) {
      free(r_list->files[i].path);
      continue;
    }
    r_list->files[unique++] = r_list->files[i];
  }
  r_list->count = unique;
  for (int i = 0; i < r_list->count; i++) {
    BC_ListedFile *file = &r_list->files[i];
    file->kind = bc_path_has_extension(file->path, ".blend") ? BC_KIND_BLEND :
                 bc_path_has_extension(file->path, ".py")    ? BC_KIND_PYTHON :
                                                               BC_KIND_DATA;
    if (!bc_file_stat(file->path, &file->size, &file->mtime)) {
      bc_list_log(&rules, BC_LOG_ERROR, "Cannot read '%s'", file->path);
      return bc_list_fail(r_list);
    }
  }
  return true;
}

/** Output of one source file: the same relative path below output_dir, so relative paths
 * (//levels/a.blend), linked libraries, imports and data file names keep working. */
static bool bc_output_path(const BC_Project *p, const char *in, char *out, size_t size)
{
  char rel[BC_PATH_MAX];
  return bc_path_relative(rel, sizeof(rel), p->source_root, in) &&
         bc_path_join(out, size, p->output_dir, rel);
}

/* -------------------------------------------------------------------------------------------- */
/* Creation: everything that can be checked before touching any output. */

/** A file name valid on every platform the game may be copied to: no separators, no characters
 * Windows rejects, not "." or "..", no trailing dot or space (Windows silently strips them). */
static bool bc_game_name_is_valid(const char *name)
{
  const size_t n = strlen(name);
  if (n == 0 || n > 200 || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
      name[n - 1] == '.' || name[n - 1] == ' ')
  {
    return false;
  }
  for (const char *c = name; *c != '\0'; c++) {
    if ((unsigned char)*c < 32 || strchr("<>:\"/\\|?*", *c) != NULL) {
      return false;
    }
  }
  return true;
}

/** Same file, compared like the file system does (case-insensitive on Windows). */
static bool bc_path_equal(const char *a, const char *b)
{
  return bc_path_is_inside(a, b) && bc_path_is_inside(b, a);
}

/** Whole small file in memory, at most \a max_size bytes. */
static bool bc_read_small_file(const char *path, const size_t max_size, uint8_t **r_data, size_t *r_size)
{
  uint64_t size;
  *r_data = NULL;
  if (!bc_file_size(path, &size) || size > max_size) {
    return false;
  }
  FILE *f = bc_fopen(path, "rb");
  uint8_t *data = (uint8_t *)malloc((size_t)size + 1);
  const bool ok = f != NULL && data != NULL && fread(data, 1, (size_t)size, f) == size;
  if (f != NULL) {
    fclose(f);
  }
  if (!ok) {
    free(data);
    return false;
  }
  *r_data = data;
  *r_size = (size_t)size;
  return true;
}

/** Icon and version information, validated now so a typo fails before any output is written. */
static bool bc_job_setup_branding(BC_Job *job, const BC_Project *p, const char *game_name)
{
  if (p->icon[0] == '\0' && p->game_version[0] == '\0' && p->company[0] == '\0' &&
      p->copyright[0] == '\0')
  {
    return true;
  }
  if (!bc_brand_supported()) {
    bc_log(job, BC_LOG_WARNING, "Icon and version information only apply to Windows games: ignored");
    return true;
  }
  BC_Branding *b = &job->brand;
  if (p->game_version[0] == '\0') {
    b->version[0] = 1;
  }
  else if (!bc_brand_parse_version(p->game_version, b->version)) {
    bc_log(job, BC_LOG_ERROR, "'%s' is not a version: use up to four numbers, like 1.2.0", p->game_version);
    return false;
  }
  if (p->icon[0] != '\0') {
    char err[256];
    if (!bc_read_small_file(p->icon, BC_BRAND_ICO_MAX_SIZE, &job->ico, &b->ico_size)) {
      bc_log(job, BC_LOG_ERROR, "Cannot read the icon '%s'", p->icon);
      return false;
    }
    if (!bc_brand_ico_check(job->ico, b->ico_size, err, sizeof(err))) {
      bc_log(job, BC_LOG_ERROR, "Invalid icon '%s': %s", p->icon, err);
      return false;
    }
    b->ico = job->ico;
  }
  snprintf(job->brand_product, sizeof(job->brand_product), "%s", game_name);
  snprintf(job->brand_company, sizeof(job->brand_company), "%s", p->company);
  snprintf(job->brand_copyright, sizeof(job->brand_copyright), "%s", p->copyright);
  b->product = job->brand_product;
  b->company = job->brand_company;
  b->copyright = job->brand_copyright;
  job->branding = true;
  return true;
}

static int bc_record_compare(const void *a, const void *b)
{
  return strcmp(((const BC_KeyRecord *)a)->path, ((const BC_KeyRecord *)b)->path);
}

/** Project or online key: load the key file, or create it on the first export; with a key per
 * update, add the key of a new update. A new key is saved before any file is sealed with it. */
static bool bc_job_setup_key(BC_Job *job, const BC_Project *p)
{
  if (p->key_mode == BC_KEY_BUILD) {
    return true;
  }
  const bool online = p->key_mode == BC_KEY_ONLINE;
  if (!bc_project_key_file(p, job->key_file, sizeof(job->key_file))) {
    bc_log(job, BC_LOG_ERROR, "Choose a key file, or save the project first (its key file then goes next to it)");
    return false;
  }
  /* A shipped key file hands out the key: refuse it whatever the mode. */
  if (bc_path_is_inside(job->dist_root, job->key_file)) {
    bc_log(job, BC_LOG_ERROR, "The key file '%s' is inside the game folder: it would ship with the game", job->key_file);
    return false;
  }
  char err[BC_PATH_MAX + 128];
  if (bc_is_file(job->key_file) && !bc_keyring_load(&job->ring, job->key_file, err, sizeof(err))) {
    bc_log(job, BC_LOG_ERROR, "%s", err);
    return false;
  }
  job->key_file_keys = true;
  job->rotation = online && p->key_rotation;
  if (!online && p->key_rotation) {
    bc_log(job, BC_LOG_WARNING, "A key per update needs an online key: the project key is used for every file");
  }
  const uint32_t newest = bc_keyring_newest(&job->ring);
  uint32_t update = newest ? newest : 1;
  if (job->rotation) {
    update = p->key_update ? p->key_update : 1;
    if (update < newest) {
      bc_log(job,
             BC_LOG_ERROR,
             "The key file already holds the key of update %u: the update number cannot go back to %u",
             newest,
             update);
      return false;
    }
  }
  const bool add = update > newest;
  job->key_reused = job->rotation && !add;
  if (add && !bc_keyring_add(&job->ring, update)) {
    bc_log(job, BC_LOG_ERROR, "The key file holds %d keys, the most one game can use", BC_KEYS_MAX);
    return false;
  }
  job->current_key = bc_keyring_find(&job->ring, update);
  /* One key without records stays in the one key form; anything else needs the full form. */
  job->key_file_single = !job->rotation && job->ring.key_count == 1 && job->ring.record_count == 0;
  if (add) {
    if (!bc_keyring_save(&job->ring, job->key_file, job->key_file_single, err, sizeof(err))) {
      bc_log(job, BC_LOG_ERROR, "%s", err);
      return false;
    }
    if (newest == 0 && online) {
      bc_log(job,
             BC_LOG_WARNING,
             "Created the content key '%s'. Keep it private, back it up and install it on your key "
             "server: without it the published game can never be updated",
             job->key_file);
    }
    else if (newest == 0) {
      bc_log(job,
             BC_LOG_WARNING,
             "Created the project key '%s'. Keep it private and back it up: updates of the game are "
             "encrypted with it",
             job->key_file);
    }
    else {
      bc_log(job,
             BC_LOG_WARNING,
             "New key for update %u in '%s': install the updated key file on the key server before "
             "publishing this update",
             update,
             job->key_file);
    }
  }
  /* The loaded records become the lookup table; this export writes a fresh set. */
  job->old_records = job->ring.records;
  job->old_record_count = job->ring.record_count;
  job->ring.records = NULL;
  job->ring.record_count = job->ring.record_capacity = 0;
  if (!online) {
    job->key_flags = BC_MANIFEST_PROJECT_KEY;
    return true;
  }

  snprintf(job->provider_rel, sizeof(job->provider_rel), "%s", p->key_provider);
  char provider_abs[BC_PATH_MAX];
  if (!bc_manifest_path_is_safe(job->provider_rel) || strlen(job->provider_rel) >= BC_MANIFEST_PATH_MAX) {
    bc_log(job,
           BC_LOG_ERROR,
           "The key provider must be a relative path inside the game folder (for example "
           "'" BC_DEFAULT_PROVIDER_DIR "/bc_provider_steam.exe')");
    return false;
  }
  if (!bc_path_join(provider_abs, sizeof(provider_abs), job->dist_root, job->provider_rel) ||
      !bc_is_file(provider_abs) || bc_path_equal(provider_abs, job->game_exe) ||
      bc_path_equal(provider_abs, job->player_abs))
  {
    bc_log(job, BC_LOG_ERROR, "Key provider not found at '%s' (copy it into the game folder first)", provider_abs);
    return false;
  }
  if (!bc_manifest_url_is_valid(p->key_url) || strlen(p->key_url) >= sizeof(job->key_url)) {
    bc_log(job, BC_LOG_ERROR, "The key server URL is too long or holds control characters");
    return false;
  }
  snprintf(job->key_url, sizeof(job->key_url), "%s", p->key_url);
  bc_project_store_notes(p, job->log, job->log_user);
  job->key_flags = BC_MANIFEST_ONLINE_KEY | (p->key_cache ? BC_MANIFEST_KEY_CACHE : 0);
  bc_log(job,
         BC_LOG_INFO,
         "Online key%s, provider '%s'%s",
         job->rotation ? " per update" : "",
         job->provider_rel,
         p->key_cache ? ", kept after the first launch" : "");
  return true;
}

int bc_file_list_changed(const BC_Project *p, const BC_FileList *list, const BC_KeyRecord *records, const int record_count)
{
  int changed = 0;
  for (int i = 0; i < list->count; i++) {
    const BC_ListedFile *file = &list->files[i];
    if (file->size == 0 && file->kind != BC_KIND_BLEND) {
      continue; /* Copied, never recorded (BC_JobFile::copy). */
    }
    /* The record path is the job's: the output, inside the game folder. */
    char out[BC_PATH_MAX], rel[BC_PATH_MAX];
    const BC_KeyRecord *record = NULL;
    if (record_count > 0 && bc_output_path(p, file->path, out, sizeof(out)) &&
        bc_path_relative(rel, sizeof(rel), bc_project_dist_root(p), out))
    {
      const BC_KeyRecord probe = {rel, {0}, 0, 0, 0};
      record = (const BC_KeyRecord *)bsearch(&probe, records, (size_t)record_count, sizeof(BC_KeyRecord), bc_record_compare);
    }
    changed += record == NULL || record->size != file->size || record->mtime != file->mtime;
  }
  return changed;
}

int bc_project_store_notes(const BC_Project *p, BC_LogFn log, void *user)
{
  const BC_KeyStore store = p->key_mode == BC_KEY_ONLINE ? bc_project_key_store(p) : BC_STORE_CUSTOM;
  const char *dist = bc_project_dist_root(p);
  if (store == BC_STORE_CUSTOM || dist[0] == '\0') {
    return 0;
  }
  int notes = 0;
  char provider[BC_PATH_MAX], dir[BC_PATH_MAX], path[BC_PATH_MAX], message[BC_PATH_MAX + 128];
  /* Only once the provider is there: a missing provider is an error of its own. */
  if (bc_path_join(provider, sizeof(provider), dist, p->key_provider) && bc_is_file(provider)) {
    bc_path_dirname(dir, sizeof(dir), provider);
    const char *library = bc_key_store_library(store);
    if (library != NULL && bc_path_join(path, sizeof(path), dir, library) && !bc_is_file(path)) {
      char shown[BC_PATH_MAX];
      bc_path_dirname(shown, sizeof(shown), p->key_provider);
      snprintf(message,
               sizeof(message),
               "%s is missing next to the key provider%s%s%s: copy it there before exporting",
               library,
               shown[0] ? " (" : "",
               shown,
               shown[0] ? "/)" : "");
      log(user, BC_LOG_WARNING, message);
      notes++;
    }
  }
  if (store == BC_STORE_STEAM && bc_path_join(path, sizeof(path), dist, "steam_appid.txt") && bc_is_file(path)) {
    log(user, BC_LOG_WARNING, "steam_appid.txt is in the game folder: it is for testing outside Steam, remove it before publishing");
    notes++;
  }
  /* The itch app gives a game the player's itch.io login only when the game's manifest asks for it. */
  if (store == BC_STORE_ITCH && bc_path_join(path, sizeof(path), dist, ".itch.toml") && !bc_is_file(path)) {
    log(user,
        BC_LOG_WARNING,
        ".itch.toml is missing in the game folder: the itch app gives the provider the player's login "
        "only for an action with scope = \"profile:me\"");
    notes++;
  }
  if (store == BC_STORE_META && p->key_cache) {
    log(user,
        BC_LOG_WARNING,
        "Meta expects an entitlement check at every launch: with Offline after 1st launch the provider "
        "runs only at the first one");
    notes++;
  }
#ifndef _WIN32
  if (store == BC_STORE_META) {
    log(user, BC_LOG_WARNING, "The Meta provider is for Windows games: export the Meta build with the Windows bc_tool");
    notes++;
  }
#endif
  return notes;
}

static BC_Job *bc_job_fail_create(BC_Job *job)
{
  bc_job_destroy(job);
  return NULL;
}

BC_Job *bc_job_create(const BC_Project *p,
                      const uint8_t key[BC_KEY_SIZE],
                      const char *launcher_path,
                      BC_LogFn log,
                      void *user)
{
  BC_Job *job = (BC_Job *)calloc(1, sizeof(BC_Job));
  if (job == NULL) {
    return NULL;
  }
  job->key = key;
  job->log = log;
  job->log_user = user;
  job->phase = BC_PHASE_HASH_PLAYER;

  if (p->source_root[0] == '\0' || !bc_is_dir(p->source_root)) {
    bc_log(job, BC_LOG_ERROR, "The source folder is not set or does not exist");
    return bc_job_fail_create(job);
  }
  if (p->output_dir[0] == '\0') {
    bc_log(job, BC_LOG_ERROR, "The output folder is not set");
    return bc_job_fail_create(job);
  }
  /* Outputs inside the sources are fine (they are skipped while scanning); sources inside the
   * outputs, or both being the same folder, would overwrite the originals. */
  if (bc_path_is_inside(p->output_dir, p->source_root)) {
    bc_log(job, BC_LOG_ERROR, "The output folder must not be, or contain, the source folder");
    return bc_job_fail_create(job);
  }
  snprintf(job->dist_root, sizeof(job->dist_root), "%s", bc_project_dist_root(p));

  /* Player: named relative to the distribution root, exactly as it will ship. With a UPBGE folder
   * it is the copy the export makes first (the folder is listed once the cheap checks passed). */
  snprintf(job->player_rel, sizeof(job->player_rel), "%s", bc_project_player(p));
  if (!bc_manifest_path_is_safe(job->player_rel)) {
    bc_log(job,
           BC_LOG_ERROR,
           "The player must be a relative path inside the game folder "
           "(for example 'engine/blenderplayer.exe')");
    return bc_job_fail_create(job);
  }
  if (!bc_path_join(job->player_abs, sizeof(job->player_abs), job->dist_root, job->player_rel)) {
    bc_log(job, BC_LOG_ERROR, "The player path is too long");
    return bc_job_fail_create(job);
  }
  if (p->upbge_dir[0] != '\0') {
    if (bc_path_is_inside(p->upbge_dir, job->dist_root) || bc_path_is_inside(job->dist_root, p->upbge_dir)) {
      bc_log(job, BC_LOG_ERROR, "The UPBGE folder and the output folder must not contain each other");
      return bc_job_fail_create(job);
    }
  }
  else if (!bc_is_file(job->player_abs)) {
    bc_log(job,
           BC_LOG_ERROR,
           "Player not found at '%s'. Set the UPBGE folder (the export then copies the runtime into "
           "%s/), or copy the UPBGE runtime there yourself before encrypting: the game only starts "
           "the exact player it was encrypted for",
           job->player_abs,
           BC_RUNTIME_DIR);
    return bc_job_fail_create(job);
  }

  if (p->main[0] == '\0') {
    bc_log(job, BC_LOG_ERROR, "The main .blend file is not set");
    return bc_job_fail_create(job);
  }

  /* Game executable: the launcher under the game's name, by default the main file's name. */
  char name[BC_PATH_MAX];
  if (p->game_name[0] != '\0') {
    snprintf(name, sizeof(name), "%s", p->game_name);
  }
  else {
    snprintf(name, sizeof(name), "%s", bc_path_basename(p->main));
    if (bc_path_has_extension(name, ".blend")) {
      name[strlen(name) - 6] = '\0';
    }
  }
  if (!bc_game_name_is_valid(name)) {
    bc_log(job, BC_LOG_ERROR, "'%s' is not a valid game name for an executable file", name);
    return bc_job_fail_create(job);
  }
  char exe_name[BC_PATH_MAX];
  snprintf(exe_name, sizeof(exe_name), "%s%s", name, bc_exe_extension());
  if (!bc_path_join(job->game_exe, sizeof(job->game_exe), job->dist_root, exe_name) ||
      bc_is_dir(job->game_exe) || bc_path_equal(job->game_exe, job->player_abs))
  {
    bc_log(job, BC_LOG_ERROR, "The game name '%s' clashes with a folder or with the player", name);
    return bc_job_fail_create(job);
  }
  if (!bc_job_setup_branding(job, p, name) || !bc_job_setup_key(job, p)) {
    return bc_job_fail_create(job);
  }
  /* Checked in both modes: an embedded export deletes a stale manifest file at this path. */
  if (!bc_path_join(job->manifest_file, sizeof(job->manifest_file), job->dist_root, BC_MANIFEST_FILENAME) ||
      bc_path_equal(job->manifest_file, job->game_exe) ||
      bc_path_equal(job->manifest_file, job->player_abs) || bc_is_dir(job->manifest_file))
  {
    bc_log(job, BC_LOG_ERROR, "The game executable or the player clashes with '%s'", BC_MANIFEST_FILENAME);
    return bc_job_fail_create(job);
  }
  if (launcher_path == NULL || !bc_is_file(launcher_path)) {
    bc_log(job,
           BC_LOG_ERROR,
           "Launcher not found at '%s': keep bc_launcher next to bc_tool, both come from the "
           "same build",
           launcher_path ? launcher_path : "?");
    return bc_job_fail_create(job);
  }
  snprintf(job->launcher_path, sizeof(job->launcher_path), "%s", launcher_path);
  job->manifest_mode = p->manifest_mode;
  job->integrity = p->integrity;
  char err[256];
  job->data_ext_count = bc_project_data_extensions(p, job->data_ext, BC_DATA_EXT_MAX, err, sizeof(err));
  if (job->data_ext_count < 0) {
    bc_log(job, BC_LOG_ERROR, "Data files: %s", err);
    return bc_job_fail_create(job);
  }
  if (p->input_count == 0) {
    bc_log(job, BC_LOG_ERROR, "There are no input files");
    return bc_job_fail_create(job);
  }

  BC_FileList list;
  if (!bc_project_list_files(p, job->data_ext, job->data_ext_count, job->log, NULL, job->log_user, &list)) {
    return bc_job_fail_create(job);
  }
  if (list.count == 0) {
    bc_file_list_free(&list);
    bc_log(job, BC_LOG_ERROR, "No files to encrypt found in the inputs");
    return bc_job_fail_create(job);
  }
  job->files = (BC_JobFile *)calloc((size_t)list.count, sizeof(BC_JobFile));
  if (job->files == NULL) {
    bc_file_list_free(&list);
    bc_log(job, BC_LOG_ERROR, "Out of memory while listing the input files");
    return bc_job_fail_create(job);
  }
  /* Said before any file is sealed: the export can still be cancelled to raise the number. */
  if (job->key_reused) {
    const int changed = bc_file_list_changed(p, &list, job->old_records, job->old_record_count);
    if (changed > 0) {
      bc_log(job,
             BC_LOG_WARNING,
             "%d file(s) changed since the last export get the key of update %u, which that export "
             "already used: if update %u is published, cancel and raise the update number",
             changed,
             job->ring.updates[job->current_key],
             job->ring.updates[job->current_key]);
    }
  }
  /* The paths change hands: the list array goes, its strings stay. */
  for (int i = 0; i < list.count; i++) {
    job->files[i].in = list.files[i].path;
    job->files[i].size = list.files[i].size;
    job->files[i].mtime = list.files[i].mtime;
    job->files[i].kind = list.files[i].kind;
  }
  job->file_count = list.count;
  free(list.files);

  /* What the UPBGE folder gives, against what an earlier export copied: reads only. */
  if (p->upbge_dir[0] != '\0') {
    char engine[BC_PATH_MAX];
    char why[BC_PATH_MAX + 256];
    if (!bc_path_join(engine, sizeof(engine), job->dist_root, BC_RUNTIME_DIR)) {
      bc_log(job, BC_LOG_ERROR, "The output folder path is too long");
      return bc_job_fail_create(job);
    }
    if (!bc_runtime_begin(&job->runtime, p->upbge_dir, engine, why, sizeof(why))) {
      bc_log(job, BC_LOG_ERROR, "%s", why);
      return bc_job_fail_create(job);
    }
    job->runtime_on = true;
  }

  /* Outputs, sizes and the main file. */
  bool main_found = false;
  for (int i = 0; i < job->file_count; i++) {
    BC_JobFile *file = &job->files[i];
    char out[BC_PATH_MAX], rel[BC_PATH_MAX];
    if (!bc_output_path(p, file->in, out, sizeof(out)) ||
        (file->out = (char *)malloc(strlen(out) + 1)) == NULL)
    {
      bc_log(job, BC_LOG_ERROR, "Invalid output path for '%s'", file->in);
      return bc_job_fail_create(job);
    }
    strcpy(file->out, out);
    job->total_bytes += 2 * file->size; /* Hashed, then sealed. */
    file->key = -1;
    file->copy = file->size == 0 && file->kind != BC_KIND_BLEND;
    if (bc_path_equal(out, job->game_exe)) {
      bc_log(job, BC_LOG_ERROR, "The game executable would overwrite '%s'", out);
      return bc_job_fail_create(job);
    }
    if (job->runtime_on && bc_path_relative(rel, sizeof(rel), job->runtime.to, out) && bc_runtime_has(&job->runtime, rel)) {
      bc_log(job, BC_LOG_ERROR, "'%s' would overwrite the UPBGE runtime file '%s/%s'", file->in, BC_RUNTIME_DIR, rel);
      return bc_job_fail_create(job);
    }
    if (strcmp(file->in, p->main) == 0) {
      if (file->kind != BC_KIND_BLEND) {
        bc_log(job, BC_LOG_ERROR, "The main file must be a .blend file");
        return bc_job_fail_create(job);
      }
      main_found = true;
      if (!bc_path_relative(job->main_out_rel, sizeof(job->main_out_rel), job->dist_root, out)) {
        bc_log(job, BC_LOG_ERROR, "The main file must end up inside the distribution folder");
        return bc_job_fail_create(job);
      }
    }
  }
  if (!main_found) {
    bc_log(job, BC_LOG_ERROR, "The main file '%s' is not among the files to encrypt", p->main);
    return bc_job_fail_create(job);
  }
  /* Checked here, before any output exists, so the manifest can never hold a truncated path. */
  if (strlen(job->player_rel) >= BC_MANIFEST_PATH_MAX ||
      strlen(job->main_out_rel) >= BC_MANIFEST_PATH_MAX)
  {
    bc_log(job, BC_LOG_ERROR, "The player or main file path is too long for the manifest");
    return bc_job_fail_create(job);
  }

  /* With a UPBGE folder the player to hash is the copy of its player, of the same size. */
  uint64_t player_size = 0;
  char source_player[BC_PATH_MAX];
  if (job->runtime_on && bc_path_join(source_player, sizeof(source_player), p->upbge_dir, BC_RUNTIME_PLAYER)) {
    bc_file_size(source_player, &player_size);
  }
  else {
    bc_file_size(job->player_abs, &player_size);
  }
  const uint64_t encrypt_bytes = job->total_bytes;
  job->total_bytes += player_size + job->runtime.copy_bytes;

  /* The player is opened by the hash phase: branding may replace the file before. */
  job->hash_buffer = (uint8_t *)malloc(BC_HASH_READ_SIZE);
  if (job->hash_buffer == NULL) {
    bc_log(job, BC_LOG_ERROR, "Out of memory");
    return bc_job_fail_create(job);
  }
  blake3_hasher_init(&job->hash_ctx);
  job->phase = job->runtime_on ? BC_PHASE_COPY_RUNTIME : job->branding ? BC_PHASE_BRAND_PLAYER : BC_PHASE_HASH_PLAYER;

  bc_log(job,
         BC_LOG_INFO,
         "%d file(s), %.1f MiB to encrypt into '%s'",
         job->file_count,
         (double)encrypt_bytes / (1024.0 * 1024.0),
         job->dist_root);
  if (job->runtime_on) {
    const BC_RuntimeCopy *c = &job->runtime;
    if (c->record_bad) {
      bc_log(job,
             BC_LOG_WARNING,
             "%s/%s cannot be read: the whole runtime is copied again, and files an older UPBGE left "
             "in %s/ stay",
             BC_RUNTIME_DIR,
             BC_RUNTIME_RECORD,
             BC_RUNTIME_DIR);
    }
    if (c->skipped > 0) {
      bc_log(job, BC_LOG_WARNING, "%d link(s) to folders in the UPBGE folder skipped", c->skipped);
    }
    if (c->copy_count > 0 || c->stale_count > 0) {
      bc_log(job,
             BC_LOG_INFO,
             "UPBGE runtime from '%s': %d of %d file(s) to copy into %s/ (%.1f MiB), %d old one(s) to remove",
             p->upbge_dir,
             c->copy_count,
             c->file_count,
             BC_RUNTIME_DIR,
             (double)c->copy_bytes / (1024.0 * 1024.0),
             c->stale_count);
    }
  }
  snprintf(job->status,
           sizeof(job->status),
           job->runtime_on ? "Copying the UPBGE runtime" :
           job->branding   ? "Branding the player" :
                             "Hashing the player");
  return job;
}

/* -------------------------------------------------------------------------------------------- */
/* Execution */

/** Stop compressing or sealing the current file and remove what it left on disk. */
static void bc_job_abort_file(BC_Job *job)
{
  if (job->compressing) {
    bc_compress_end(&job->compressor, true);
    job->compressing = false;
  }
  if (job->sealing) {
    bc_seal_abort(&job->sealer);
    job->sealing = false;
  }
  if (job->compressed[0] != '\0') {
    bc_remove(job->compressed);
    job->compressed[0] = '\0';
  }
}

static void bc_job_set_failed(BC_Job *job)
{
  bc_job_abort_file(job);
  job->phase = BC_PHASE_FAILED;
  snprintf(job->status, sizeof(job->status), "Failed");
}

/** Brand \a path, warning when that voids the signature of \a signed_source. Errors are logged. */
static BC_BrandResult bc_job_brand(BC_Job *job, const char *path, const char *signed_source, const char *original_filename)
{
  char err[BC_PATH_MAX + 128];
  job->brand.original_filename = original_filename;
  /* Checked before: the update itself may drop the signature table. */
  const bool was_signed = bc_exe_has_signature(signed_source);
  const BC_BrandResult result = bc_brand_exe(path, &job->brand, err, sizeof(err));
  if (result == BC_BRAND_ERROR) {
    bc_log(job, BC_LOG_ERROR, "%s", err);
    return result;
  }
  if (result == BC_BRAND_CHANGED && was_signed) {
    bc_log(job,
           BC_LOG_WARNING,
           "'%s' is signed, but the icon or version information changed: sign %s",
           bc_display(job, signed_source),
           signed_source == path ? "it again, then export again (a player that is already "
                                   "branded is left untouched)" :
                                   "the exported game executable");
  }
  return result;
}

/* One file removed or one buffer copied (bc_runtime.h). */
static void bc_job_copy_runtime(BC_Job *job)
{
  BC_RuntimeCopy *c = &job->runtime;
  char err[BC_PATH_MAX + 128];
  const uint64_t before = c->done_bytes;
  const int result = bc_runtime_step(c, job->hash_buffer, BC_HASH_READ_SIZE, err, sizeof(err));
  job->done_bytes += c->done_bytes - before;
  if (result < 0) {
    bc_log(job, BC_LOG_ERROR, "%s", err);
    bc_job_set_failed(job);
    return;
  }
  const char *current = bc_runtime_current(c);
  if (current != NULL) {
    snprintf(job->status, sizeof(job->status), BC_RUNTIME_DIR "/%s", current);
  }
  if (result > 0) {
    return;
  }
  if (c->copied + c->removed > 0) {
    bc_log(job,
           BC_LOG_INFO,
           "UPBGE runtime: %d file(s) copied (%.1f MiB), %d old one(s) removed, %d up to date",
           c->copied,
           (double)c->done_bytes / (1024.0 * 1024.0),
           c->removed,
           c->file_count - c->copied);
  }
  else {
    bc_log(job, BC_LOG_INFO, "UPBGE runtime up to date (%d files in %s/)", c->file_count, BC_RUNTIME_DIR);
  }
  /* Failing to record costs the next export a full copy, never a broken game. */
  if (!bc_runtime_save(c, err, sizeof(err))) {
    bc_log(job, BC_LOG_WARNING, "%s: the next export copies the whole runtime again", err);
  }
  job->phase = job->branding ? BC_PHASE_BRAND_PLAYER : BC_PHASE_HASH_PLAYER;
  snprintf(job->status, sizeof(job->status), job->branding ? "Branding the player" : "Hashing the player");
}

/* Before hashing: the manifest must authenticate the player as shipped. Blocking, but it only
 * rewrites the player when the icon or version information differ. */
static void bc_job_brand_player(BC_Job *job)
{
  uint64_t before = 0, after = 0;
  bc_file_size(job->player_abs, &before);
  const BC_BrandResult result = bc_job_brand(job, job->player_abs, job->player_abs, bc_path_basename(job->player_rel));
  if (result == BC_BRAND_ERROR) {
    bc_job_set_failed(job);
    return;
  }
  if (result == BC_BRAND_CHANGED) {
    bc_log(job, BC_LOG_INFO, "Player icon and version information updated");
    if (bc_file_size(job->player_abs, &after)) {
      job->total_bytes = job->total_bytes - before + after;
    }
  }
  job->phase = BC_PHASE_HASH_PLAYER;
  snprintf(job->status, sizeof(job->status), "Hashing the player");
}

static void bc_job_hash_player(BC_Job *job)
{
  if (job->player_file == NULL && (job->player_file = bc_fopen(job->player_abs, "rb")) == NULL) {
    bc_log(job, BC_LOG_ERROR, "Cannot read the player '%s'", job->player_abs);
    bc_job_set_failed(job);
    return;
  }
  const size_t n = fread(job->hash_buffer, 1, BC_HASH_READ_SIZE, job->player_file);
  blake3_hasher_update(&job->hash_ctx, job->hash_buffer, n);
  job->done_bytes += n;
  if (n == BC_HASH_READ_SIZE) {
    return;
  }
  const bool error = ferror(job->player_file) != 0;
  fclose(job->player_file);
  job->player_file = NULL;
  if (error) {
    bc_log(job, BC_LOG_ERROR, "Read error while hashing the player '%s'", job->player_abs);
    bc_job_set_failed(job);
    return;
  }
  blake3_hasher_finalize(&job->hash_ctx, job->player_hash, BC_PLAYER_HASH_SIZE);
  bc_log(job, BC_LOG_INFO, "Player '%s' registered", job->player_rel);
  job->phase = BC_PHASE_SEAL;
}

/** Pick the key of a hashed file (see BC_Job): build key, the only online key, or with a key per
 * update its earlier key when its plaintext did not change. */
static bool bc_job_choose_key(BC_Job *job, BC_JobFile *file)
{
  if (!job->key_file_keys || !job->rotation) {
    file->key = job->key_file_keys ? job->current_key : -1;
    return true;
  }
  char rel[BC_PATH_MAX];
  if (!bc_path_relative(rel, sizeof(rel), job->dist_root, file->out)) {
    return false;
  }
  const BC_KeyRecord probe = {rel, {0}, 0, 0, 0};
  const BC_KeyRecord *old = job->old_record_count > 0 ?
                                (const BC_KeyRecord *)bsearch(&probe, job->old_records, (size_t)job->old_record_count, sizeof(BC_KeyRecord), bc_record_compare) :
                                NULL;
  int index = -1;
  if (old != NULL && memcmp(old->hash, file->hash, BC_PLAIN_HASH_SIZE) == 0) {
    index = bc_keyring_find(&job->ring, old->update);
  }
  if (index < 0) {
    index = job->current_key;
    job->changed_files++;
  }
  else {
    job->unchanged_files++;
  }
  file->key = index;
  return bc_keyring_set_record(&job->ring, rel, file->hash, job->ring.updates[index], file->size, file->mtime);
}

/** One slice of the plaintext hash pass of the current file. */
static void bc_job_hash_file(BC_Job *job, BC_JobFile *file)
{
  const bool first = job->file_hash_in == NULL;
  if (first) {
    job->file_hash_in = bc_fopen(file->in, "rb");
    if (job->file_hash_in == NULL) {
      bc_log(job, BC_LOG_ERROR, "Cannot read '%s'", file->in);
      bc_job_set_failed(job);
      return;
    }
    crypto_blake2b_init(&job->file_hash_ctx, BC_PLAIN_HASH_SIZE);
    snprintf(job->status, sizeof(job->status), "%s", bc_display(job, file->in));
  }
  const size_t n = fread(job->hash_buffer, 1, BC_HASH_READ_SIZE, job->file_hash_in);
  crypto_blake2b_update(&job->file_hash_ctx, job->hash_buffer, n);
  job->done_bytes += n;
  if (first) {
    file->compress = file->kind == BC_KIND_BLEND && bc_blend_is_uncompressed(job->hash_buffer, n);
  }
  if (n == BC_HASH_READ_SIZE) {
    return;
  }
  const bool error = ferror(job->file_hash_in) != 0;
  fclose(job->file_hash_in);
  job->file_hash_in = NULL;
  crypto_blake2b_final(&job->file_hash_ctx, file->hash);
  file->hashed = true;
  if (error || !bc_job_choose_key(job, file)) {
    bc_log(job, BC_LOG_ERROR, "Cannot read '%s'", file->in);
    bc_job_set_failed(job);
  }
}

/** Write an empty file as it is (see BC_JobFile::copy). */
static void bc_job_copy_empty(BC_Job *job, BC_JobFile *file)
{
  uint64_t size = 1;
  if (!bc_file_size(file->in, &size) || size != 0) {
    bc_log(job, BC_LOG_ERROR, "'%s' changed while it was being read", file->in);
    bc_job_set_failed(job);
    return;
  }
  if (bc_is_file(file->out) && bc_file_size(file->out, &size) && size == 0) {
    job->kept_files++;
    bc_log(job, BC_LOG_INFO, "Up to date %s", bc_display(job, file->out));
    job->current++;
    return;
  }
  char dir[BC_PATH_MAX];
  bc_path_dirname(dir, sizeof(dir), file->out);
  FILE *f = bc_mkdir_p(dir) ? bc_fopen(file->out, "wb") : NULL;
  if (f == NULL || fclose(f) != 0) {
    bc_log(job, BC_LOG_ERROR, "Cannot write '%s'", file->out);
    bc_job_set_failed(job);
    return;
  }
  bc_log(job, BC_LOG_INFO, "Copied %s (empty: nothing to encrypt)", bc_display(job, file->out));
  job->current++;
}

static void bc_job_seal(BC_Job *job)
{
  if (job->current == job->file_count) {
    job->phase = BC_PHASE_GAME_EXE;
    return;
  }
  BC_JobFile *file = &job->files[job->current];
  char err[BC_PATH_MAX + 128];
  if (file->copy) {
    bc_job_copy_empty(job, file);
    return;
  }
  if (!file->hashed) {
    bc_job_hash_file(job, file);
    return;
  }
  const uint8_t *key = file->key < 0 ? job->key : job->ring.keys[file->key];
  if (!job->sealing && !job->compressing) {
    /* Made from the same source with the same key: the container stands (byte for byte, even if
     * this zstd would compress differently), so neither compress, encrypt nor rewrite it.
     * Re-exporting an unchanged game costs one hash pass. */
    if (bc_seal_output_is_current(key, file->kind, file->out, file->hash)) {
      job->kept_files++;
      job->done_bytes += file->size;
      bc_log(job, BC_LOG_INFO, "Up to date %s", bc_display(job, file->out));
      job->current++;
      return;
    }
    job->current_base = job->done_bytes;
    snprintf(job->status, sizeof(job->status), "%s", bc_display(job, file->in));
    if (file->compress) {
      const int n = snprintf(job->compressed, sizeof(job->compressed), "%s.zst.tmp", file->out);
      char dir[BC_PATH_MAX];
      bc_path_dirname(dir, sizeof(dir), file->out);
      if (n < 0 || (size_t)n >= sizeof(job->compressed) || !bc_mkdir_p(dir)) {
        job->compressed[0] = '\0';
        bc_log(job, BC_LOG_ERROR, "Cannot write '%s'", file->out);
        bc_job_set_failed(job);
        return;
      }
      if (!bc_compress_begin(&job->compressor, file->in, job->compressed, err, sizeof(err))) {
        job->compressed[0] = '\0';
        bc_log(job, BC_LOG_ERROR, "%s", err);
        bc_job_set_failed(job);
        return;
      }
      job->compressing = true;
      job->total_bytes += file->size; /* One more pass over the source. */
      return;
    }
    if (!bc_seal_begin(&job->sealer, key, file->kind, file->in, file->out, file->hash, file->hash, err, sizeof(err))) {
      bc_log(job, BC_LOG_ERROR, "%s", err);
      bc_job_set_failed(job);
      return;
    }
    job->sealing = true;
  }
  if (job->compressing) {
    const int result = bc_compress_step(&job->compressor, err, sizeof(err));
    if (result < 0) {
      job->compressing = false; /* The compressor already removed its output. */
      job->compressed[0] = '\0';
      bc_log(job, BC_LOG_ERROR, "%s", err);
      bc_job_set_failed(job);
      return;
    }
    job->done_bytes = job->current_base + job->compressor.in_done;
    if (result == 1) {
      return;
    }
    job->compressing = false;
    job->current_base = job->done_bytes;
    /* The compressed copy is the plaintext; the source id still names the source. */
    if (!bc_seal_begin(&job->sealer, key, file->kind, job->compressed, file->out, job->compressor.out_hash, file->hash, err, sizeof(err))) {
      bc_log(job, BC_LOG_ERROR, "%s", err);
      bc_job_set_failed(job);
      return;
    }
    job->sealing = true;
  }
  const int result = bc_seal_step(&job->sealer, err, sizeof(err));
  if (result < 0) {
    job->sealing = false; /* The sealer already removed its partial output. */
    bc_log(job, BC_LOG_ERROR, "%s", err);
    bc_job_set_failed(job);
    return;
  }
  /* Progress in source bytes, also while sealing a compressed copy of another size. */
  const uint64_t sealed = bc_seal_bytes_done(&job->sealer);
  const uint64_t plain = job->sealer.header.plain_size;
  job->done_bytes = job->current_base + (plain ? (uint64_t)((double)sealed / (double)plain * (double)file->size) : 0);
  if (result == 0) {
    job->sealing = false;
    job->done_bytes = job->current_base + file->size;
    if (job->compressed[0] != '\0') {
      bc_remove(job->compressed);
      job->compressed[0] = '\0';
      bc_log(job, BC_LOG_INFO, "Encrypted %s (compressed to %.0f%%)", bc_display(job, file->out),
             100.0 * (double)plain / (double)(file->size ? file->size : 1));
    }
    else {
      bc_log(job, BC_LOG_INFO, "Encrypted %s", bc_display(job, file->out));
    }
    job->current++;
  }
}

static void bc_job_write_game_exe(BC_Job *job)
{
  BC_Manifest manifest;
  memset(&manifest, 0, sizeof(manifest));
  memcpy(manifest.player_hash, job->player_hash, BC_PLAYER_HASH_SIZE);
  if (job->key_flags & BC_MANIFEST_ONLINE_KEY) {
    /* Every key some file uses, oldest update first: the launcher fetches exactly these. */
    bool used[BC_KEYS_MAX] = {false};
    for (int i = 0; i < job->file_count; i++) {
      if (!job->files[i].copy) {
        used[job->files[i].key] = true;
      }
    }
    for (int i = 0; i < job->ring.key_count; i++) {
      if (used[i]) {
        bc_key_id(job->ring.keys[i], manifest.key_ids[manifest.key_count++]);
      }
    }
    manifest.flags = job->key_flags;
    /* Lengths validated by bc_job_setup_key. */
    memcpy(manifest.provider_path, job->provider_rel, strlen(job->provider_rel) + 1);
    memcpy(manifest.key_url, job->key_url, strlen(job->key_url) + 1);
  }
  else if (job->key_flags & BC_MANIFEST_PROJECT_KEY) {
    /* The project key travels in the manifest, masked: never 32 bytes of the file as itself. */
    uint8_t mask[BC_KEY_SIZE];
    manifest.flags = job->key_flags;
    manifest.key_count = 1;
    bc_key_id(job->ring.keys[job->current_key], manifest.key_ids[0]);
    bc_manifest_key_mask(job->key, &manifest, mask);
    for (int i = 0; i < BC_KEY_SIZE; i++) {
      manifest.masked_key[i] = job->ring.keys[job->current_key][i] ^ mask[i];
    }
    crypto_wipe(mask, sizeof(mask));
  }
  /* Lengths validated by bc_job_create. */
  memcpy(manifest.player_path, job->player_rel, strlen(job->player_rel) + 1);
  memcpy(manifest.main_path, job->main_out_rel, strlen(job->main_out_rel) + 1);
  char err[BC_PATH_MAX + 128];
  if (job->integrity != BC_INTEGRITY_PLAYER) {
    /* Last step before the executable itself, so every file the export wrote is in place. The
     * executable (it carries this manifest) and the player (hashed on its own) are left out. The
     * Python level also removes the bytecode left by test runs, so the game ships without any:
     * installed where the player cannot write, none can ever appear (bc_native.h). */
    const bool python = job->integrity == BC_INTEGRITY_PYTHON;
    char exe_rel[BC_PATH_MAX];
    const char *skip[2] = {exe_rel, job->player_rel};
    static BC_NativeScan scan;
    if (!bc_path_relative(exe_rel, sizeof(exe_rel), job->dist_root, job->game_exe) ||
        !bc_native_digest(job->dist_root, skip, 2, python, manifest.native_digest, &scan))
    {
      if (scan.locked[0] != '\0') {
        bc_log(job, BC_LOG_ERROR, "Cannot remove the Python bytecode file '%s'", scan.locked);
      }
      else {
        bc_log(job, BC_LOG_ERROR, "Cannot read the code files (.dll, .so, .dylib, .pyd, .exe%s) of '%s'", python ? ", .py, .pth, .zip" : "", job->dist_root);
      }
      bc_job_set_failed(job);
      return;
    }
    manifest.flags |= BC_MANIFEST_NATIVE_DIGEST | (python ? BC_MANIFEST_PYTHON_CHECK : 0);
    if (scan.bytecode_removed > 0) {
      bc_log(job, BC_LOG_INFO, "Removed %d Python bytecode file(s) from the game folder", scan.bytecode_removed);
    }
    bc_log(job,
           BC_LOG_INFO,
           "%s check: %d file(s), %.1f MB, verified at every launch. Export again after changing any of them",
           python ? "Native code and Python" : "Native code",
           scan.files,
           (double)scan.bytes / (1024.0 * 1024.0));
  }
  const bool external = job->manifest_mode == BC_MANIFEST_EXTERNAL;
  /* Branded games start from a branded copy of the launcher: resources first, manifest after. */
  char branded[BC_PATH_MAX + 16];
  const char *launcher = job->launcher_path;
  if (job->branding) {
    snprintf(branded, sizeof(branded), "%s.brand.tmp", job->game_exe);
    if (!bc_embed_write(job->launcher_path, branded, NULL, job->key, err, sizeof(err))) {
      bc_log(job, BC_LOG_ERROR, "%s", err);
      bc_job_set_failed(job);
      return;
    }
    if (bc_job_brand(job, branded, job->launcher_path, bc_path_basename(job->game_exe)) == BC_BRAND_ERROR) {
      bc_remove(branded);
      bc_job_set_failed(job);
      return;
    }
    launcher = branded;
  }
  const bool written = bc_embed_write(launcher, job->game_exe, external ? NULL : &manifest, job->key, err, sizeof(err));
  if (launcher != job->launcher_path) {
    bc_remove(branded);
  }
  if (!written ||
      (external && !bc_manifest_file_write(job->manifest_file, &manifest, job->key, err, sizeof(err))))
  {
    bc_log(job, BC_LOG_ERROR, "%s", err);
    bc_job_set_failed(job);
    return;
  }
  /* A file left by an earlier external export would be ignored by the launcher (the embedded
   * manifest wins), but shipping it would only confuse: remove it. */
  if (!external && bc_is_file(job->manifest_file) && bc_remove(job->manifest_file)) {
    bc_log(job, BC_LOG_INFO, "Removed the old %s (the manifest is now inside the executable)", BC_MANIFEST_FILENAME);
  }
  bc_log(job,
         BC_LOG_INFO,
         "Game executable written: %s starts '%s' with '%s'%s",
         bc_display(job, job->game_exe),
         job->player_rel,
         job->main_out_rel,
         external ? " (manifest in " BC_MANIFEST_FILENAME ")" : "");
  bc_log(job,
         BC_LOG_INFO,
         "%d file(s) encrypted, %d already up to date",
         job->file_count - job->kept_files,
         job->kept_files);
  if (job->rotation) {
    /* The records only decide which key unchanged files keep: failing to save them costs a larger
     * next update, never a broken game (every key is already in the file). */
    if (!bc_keyring_save(&job->ring, job->key_file, false, err, sizeof(err))) {
      bc_log(job, BC_LOG_WARNING, "%s: the next update may encrypt unchanged files again", err);
    }
    bc_log(job,
           BC_LOG_INFO,
           "Update %u: %d file(s) with its key, %d unchanged with earlier keys; the game uses %d key(s)",
           job->ring.updates[job->current_key],
           job->changed_files,
           job->unchanged_files,
           manifest.key_count);
  }
  job->phase = BC_PHASE_DONE;
  snprintf(job->status, sizeof(job->status), "Done");
}

int bc_job_step(BC_Job *job, const double budget_seconds)
{
  const double deadline = bc_time_seconds() + budget_seconds;
  while (job->phase != BC_PHASE_DONE && job->phase != BC_PHASE_FAILED) {
    switch (job->phase) {
      case BC_PHASE_COPY_RUNTIME:
        bc_job_copy_runtime(job);
        break;
      case BC_PHASE_BRAND_PLAYER:
        bc_job_brand_player(job);
        break;
      case BC_PHASE_HASH_PLAYER:
        bc_job_hash_player(job);
        break;
      case BC_PHASE_SEAL:
        bc_job_seal(job);
        break;
      case BC_PHASE_GAME_EXE:
        bc_job_write_game_exe(job);
        break;
      default:
        break;
    }
    /* One clock read per 64 KiB chunk or 1 MiB hash block: negligible next to the work. */
    if (bc_time_seconds() >= deadline) {
      break;
    }
  }
  if (job->phase == BC_PHASE_DONE) {
    return 0;
  }
  return job->phase == BC_PHASE_FAILED ? -1 : 1;
}

double bc_job_progress(const BC_Job *job)
{
  if (job->phase == BC_PHASE_DONE) {
    return 1.0;
  }
  return job->total_bytes ? (double)job->done_bytes / (double)job->total_bytes : 0.0;
}

const char *bc_job_status(const BC_Job *job)
{
  return job->status;
}

void bc_job_destroy(BC_Job *job)
{
  if (job == NULL) {
    return;
  }
  bc_job_abort_file(job);
  if (job->player_file != NULL) {
    fclose(job->player_file);
  }
  if (job->file_hash_in != NULL) {
    fclose(job->file_hash_in);
  }
  for (int i = 0; i < job->old_record_count; i++) {
    free(job->old_records[i].path);
  }
  free(job->old_records);
  bc_runtime_end(&job->runtime);
  bc_keyring_free(&job->ring);
  for (int i = 0; i < job->file_count; i++) {
    free(job->files[i].in);
    free(job->files[i].out);
  }
  free(job->files);
  free(job->hash_buffer);
  free(job->ico);
  free(job);
}
