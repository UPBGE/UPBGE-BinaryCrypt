/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Batch project (.bcproj): what to encrypt and how. Plain text, one `key = value` per line, '#'
 * comments, paths relative to the project file so a project can move with its game:
 *
 *   version = 1
 *   source_root = .               # tree of the game sources (.blend files, Python modules...)
 *   output_mode = mirror          # mirror | inplace
 *   output_dir = dist             # mirror only: encrypted copy of the tree, same names
 *   game_name = MyGame            # game executable name (".exe" added on Windows); optional,
 *                                 # defaults to the main file name without ".blend"
 *   manifest = embedded           # embedded | external (binarycrypt.manifest next to the game
 *                                 # executable, which stays a byte-identical launcher copy)
 *   icon = game.ico               # Windows: icon of the game executable and window; optional
 *   game_version = 1.2.0          # Windows version information, all three optional. Setting
 *   company = My Studio           # any of icon/game_version/company/copyright brands the game
 *   copyright = (c) 2026 My Studio  # executable and the player (see bc_brand.h)
 *   key = project                 # project (default): a key of this project, stored masked in the
 *                                 # game executable | online: from a key server (bc_envelope.h) |
 *                                 # build: the key compiled into this tool and its launcher
 *   key_file = keys/mygame.key    # project and online: the key, created on the first export;
 *                                 # private; default: next to the project file, named after it
 *   key_provider = engine/bc_provider_steam.exe  # online: relative to the distribution root
 *   key_url = https://keys.example.com/key       # online: given to the provider, optional
 *   key_cache = none              # online: none | permanent (kept after the first launch)
 *   key_rotation = off            # online: off (one key) | per_update (a new key per update,
 *   key_update = 1                # unchanged files keep theirs); key_update numbers the update
 *   integrity = python            # what the game executable checks before every launch:
 *                                 # player | native (+ every .dll, .so, .dylib, .pyd, .exe of the
 *                                 # game folder) | python (default: + .py, .pyw, .pth, .zip;
 *                                 # Python bytecode removed) (bc_native.h)
 *   player = engine/blenderplayer.exe  # relative to the distribution root, hashed by the tool
 *   main = game.blend             # the blend the game executable starts
 *   data_extensions = .json .txt  # mirror only: folders also give these files, read in the
 *                                 # game with bge.logic.decryptFile(); optional
 *   input = game.blend            # a file of any kind, or a folder scanned recursively for
 *   input = levels                # *.blend, and in mirror mode *.py and data_extensions files
 *
 * A '#' preceded by a space or a tab starts a comment; double quotes keep it, and leading or
 * trailing spaces, in a value.
 *
 * Distribution root (where the game executable lives, with the runtime in engine/ by
 * convention): output_dir in mirror mode, source_root in inplace mode. Inplace writes
 * "name.upbgebc" next to each "name.blend". */

#ifndef BC_PROJECT_H
#define BC_PROJECT_H

#include <stdbool.h>
#include <stddef.h>

#include "bc_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BC_PROJECT_VERSION 1
#define BC_PROJECT_EXTENSION ".bcproj"
#define BC_INPLACE_EXTENSION ".upbgebc"
#define BC_GAME_NAME_MAX 256
#define BC_PROJECT_TEXT_MAX 256
#define BC_PROJECT_VERSION_MAX 32
#define BC_PROJECT_URL_MAX 1024
/** Limits of #bc_project_data_extensions. */
#define BC_DATA_EXT_MAX 32
#define BC_DATA_EXT_SIZE 32
/** Conventional player location inside the distribution root (bc_exe_extension() appended). */
#define BC_DEFAULT_PLAYER "engine/blenderplayer"

/** Integrity check levels. The order is the GUI's. */
typedef enum BC_Integrity {
  /** The player executable only. */
  BC_INTEGRITY_PLAYER = 0,
  /** And the native code of the game folder. */
  BC_INTEGRITY_NATIVE = 1,
  /** And its Python files; Python bytecode is removed instead of checked. */
  BC_INTEGRITY_PYTHON = 2,
} BC_Integrity;

/** Where the content key comes from. The order is the GUI's, the zero value the default. */
typedef enum BC_KeyMode {
  /** A key of this project, from its key file, carried masked in the manifest. */
  BC_KEY_PROJECT = 0,
  /** Keys from the project's key file, handed out by a key server through the provider. */
  BC_KEY_ONLINE = 1,
  /** The key built into bc_tool and the launcher. */
  BC_KEY_BUILD = 2,
} BC_KeyMode;

typedef enum BC_ManifestMode {
  BC_MANIFEST_EMBEDDED = 0,
  BC_MANIFEST_EXTERNAL = 1,
} BC_ManifestMode;

typedef enum BC_OutputMode {
  BC_OUTPUT_MIRROR = 0,
  BC_OUTPUT_INPLACE = 1,
} BC_OutputMode;

/** In memory every path is absolute and normalized, except #player which is always relative to
 * the distribution root (it names the file as shipped next to the launcher). */
typedef struct BC_Project {
  /** Absolute path of the project file once loaded or saved, else empty: the default key file
   * goes next to it. Not stored in the file. */
  char project_file[BC_PATH_MAX];
  char source_root[BC_PATH_MAX];
  BC_OutputMode output_mode;
  char output_dir[BC_PATH_MAX];
  char game_name[BC_GAME_NAME_MAX];
  BC_ManifestMode manifest_mode;
  /** Windows branding, empty when unused: icon is an absolute path. */
  char icon[BC_PATH_MAX];
  char game_version[BC_PROJECT_VERSION_MAX];
  char company[BC_PROJECT_TEXT_MAX];
  char copyright[BC_PROJECT_TEXT_MAX];
  /** Content key: key_file is absolute (empty: bc_project_key_file() picks it), key_provider
   * relative like #player. */
  BC_KeyMode key_mode;
  char key_file[BC_PATH_MAX];
  char key_provider[BC_PATH_MAX];
  char key_url[BC_PROJECT_URL_MAX];
  bool key_cache;
  bool key_rotation;
  uint32_t key_update;
  /** What the game executable checks before every launch (bc_native.h). */
  BC_Integrity integrity;
  char player[BC_PATH_MAX];
  char main[BC_PATH_MAX];
  /** Extensions of the data files folder inputs give, as typed ("json, .txt"); empty: none. */
  char data_extensions[BC_PROJECT_TEXT_MAX];
  char **inputs;
  int input_count;
  int input_capacity;
} BC_Project;

void bc_project_init(BC_Project *p);
void bc_project_free(BC_Project *p);

/** Add an absolute path (normalized on the way in). Duplicates are ignored. */
bool bc_project_add_input(BC_Project *p, const char *path);
void bc_project_remove_input(BC_Project *p, int index);
void bc_project_clear_inputs(BC_Project *p);

/**
 * Split #BC_Project.data_extensions (separated by spaces, commas or semicolons; "json", ".json"
 * and "*.json" alike) into dot-prefixed extensions.
 * \return their number, or -1 with the reason in \a err: a malformed list, or an extension that is
 * not data (.blend, .py, or code the player loads: encrypted, it would no longer load).
 */
int bc_project_data_extensions(const BC_Project *p, char out[][BC_DATA_EXT_SIZE], int max, char *err, size_t err_size);

/** Where the launcher, manifest and player live (see file comment). */
const char *bc_project_dist_root(const BC_Project *p);

/** The key file: key_file, else "<project file name>.key" next to the project file. False when
 * neither exists (an unsaved project without a key file). */
bool bc_project_key_file(const BC_Project *p, char *out, size_t size);

bool bc_project_load(BC_Project *p, const char *file_path, char *err, size_t err_size);
bool bc_project_save(const BC_Project *p, const char *file_path, char *err, size_t err_size);

#ifdef __cplusplus
}
#endif

#endif /* BC_PROJECT_H */
