/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Windows executable branding: the icon group "APPICON" and the version information.
 *
 * GHOST loads the window icon (title bar, taskbar, Alt-Tab) with LoadIcon(hInstance, "APPICON")
 * from the player, and Explorer shows the first icon group of an executable, which is "APPICON"
 * too (named resources sort before numbered ones). Task Manager and Explorer read the version
 * information. bc_tool brands the player before hashing it and the game executable before the
 * manifest is appended, on every export.
 *
 * Only the APPICON group and the version resource change: other icon groups (the player's .blend
 * file icon is group 1), its manifest and everything else stay as they are. Writing uses the Win32
 * resource update API, so it exists in Windows builds only, which are also the only builds that
 * produce Windows games. Parsing and validation are portable. */

#ifndef BC_BRAND_H
#define BC_BRAND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BC_BRAND_ICON_GROUP "APPICON"
/** Larger .ico files are refused: a 256 px PNG icon is a few hundred KiB at most. */
#define BC_BRAND_ICO_MAX_SIZE (16u << 20)
#define BC_BRAND_ICO_MAX_IMAGES 64

typedef struct BC_Branding {
  /** Whole .ico file (validated by bc_brand_ico_check), or NULL to keep the current icon. */
  const uint8_t *ico;
  size_t ico_size;
  /** UTF-8. product is the game name (ProductName, FileDescription, InternalName); company and
   * copyright may be empty (then omitted). */
  const char *product;
  const char *company;
  const char *copyright;
  const char *original_filename;
  uint16_t version[4];
} BC_Branding;

typedef enum BC_BrandResult {
  BC_BRAND_ERROR = -1,
  BC_BRAND_UNCHANGED = 0,
  BC_BRAND_CHANGED = 1,
} BC_BrandResult;

/** "1", "1.2", "1.2.3" or "1.2.3.4", each part 0..65535; missing parts are 0. */
bool bc_brand_parse_version(const char *text, uint16_t r_version[4]);

/** Structure of a .ico file: header, entries inside the file, PNG or DIB images. */
bool bc_brand_ico_check(const uint8_t *ico, size_t size, char *err, size_t err_size);

/** True when this build can brand executables (Windows). */
bool bc_brand_supported(void);

/**
 * Apply \a b to the executable at \a exe_path, replacing it atomically. When its icon group and
 * version information already match, the file is not touched at all (BC_BRAND_UNCHANGED): an
 * unchanged player keeps its code signature and its hash.
 */
BC_BrandResult bc_brand_exe(const char *exe_path, const BC_Branding *b, char *err, size_t err_size);

#ifdef __cplusplus
}
#endif

#endif /* BC_BRAND_H */
