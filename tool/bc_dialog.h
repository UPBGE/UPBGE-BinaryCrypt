/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Native file dialogs: Win32 common dialogs on Windows, osascript on macOS, zenity or kdialog on
 * Linux (the same strategy as tinyfiledialogs, reduced to the three calls the tool needs). Only
 * constant strings from this program are ever passed to a shell, never user paths.
 *
 * Kept free of raylib headers on purpose: raylib and windows.h define conflicting names. */

#ifndef BC_DIALOG_H
#define BC_DIALOG_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Separator between paths returned by #bc_dialog_open_files (never valid inside a path). */
#define BC_DIALOG_SEPARATOR '\n'

typedef enum BC_DialogResult {
  BC_DIALOG_OK,
  BC_DIALOG_CANCELLED,
  /** No dialog backend on this system (Linux without zenity or kdialog). */
  BC_DIALOG_UNAVAILABLE,
} BC_DialogResult;

/** \a extension without dot ("blend"), or NULL for any file. Paths are written to \a out separated
 * by #BC_DIALOG_SEPARATOR, absolute and normalized. */
BC_DialogResult bc_dialog_open_files(const char *title,
                                     const char *extension,
                                     bool multiple,
                                     char *out,
                                     size_t size);
BC_DialogResult bc_dialog_save_file(const char *title,
                                    const char *extension,
                                    char *out,
                                    size_t size);
BC_DialogResult bc_dialog_pick_folder(const char *title, char *out, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* BC_DIALOG_H */
