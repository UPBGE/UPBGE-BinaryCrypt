/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_brand.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc_platform.h"

static uint16_t bc_ld16(const uint8_t *p)
{
  return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t bc_ld32(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool bc_brand_parse_version(const char *text, uint16_t r_version[4])
{
  memset(r_version, 0, 4 * sizeof(uint16_t));
  const char *s = text;
  for (int part = 0; part < 4; part++) {
    if (*s < '0' || *s > '9') {
      return false;
    }
    uint32_t n = 0;
    while (*s >= '0' && *s <= '9') {
      n = n * 10 + (uint32_t)(*s++ - '0');
      if (n > 0xFFFF) {
        return false;
      }
    }
    r_version[part] = (uint16_t)n;
    if (*s == '\0') {
      return true;
    }
    if (*s++ != '.') {
      return false;
    }
  }
  return false; /* A fifth part. */
}

/* .ico file: ICONDIR (u16 0, u16 1, u16 count), then count ICONDIRENTRY of 16 bytes:
 * u8 width, u8 height, u8 colors, u8 0, u16 planes, u16 bpp, u32 bytes, u32 offset. Images are PNG
 * files or DIBs starting with a 40 byte BITMAPINFOHEADER. */
bool bc_brand_ico_check(const uint8_t *ico, const size_t size, char *err, const size_t err_size)
{
  if (size < 6 || size > BC_BRAND_ICO_MAX_SIZE || bc_ld16(ico) != 0 || bc_ld16(ico + 2) != 1) {
    snprintf(err, err_size, "not an .ico file");
    return false;
  }
  const size_t count = bc_ld16(ico + 4);
  const size_t table_end = 6 + 16 * count;
  if (count == 0 || count > BC_BRAND_ICO_MAX_IMAGES || table_end > size) {
    snprintf(err, err_size, "the icon holds no images or more than %d", BC_BRAND_ICO_MAX_IMAGES);
    return false;
  }
  for (size_t i = 0; i < count; i++) {
    const uint8_t *entry = ico + 6 + 16 * i;
    const size_t bytes = bc_ld32(entry + 8);
    const size_t offset = bc_ld32(entry + 12);
    if (bytes < 8 || offset < table_end || offset > size || bytes > size - offset) {
      snprintf(err, err_size, "image %d lies outside the icon file", (int)i + 1);
      return false;
    }
    const uint8_t *image = ico + offset;
    if (memcmp(image, "\x89PNG", 4) != 0 && bc_ld32(image) != 40) {
      snprintf(err, err_size, "image %d is neither PNG nor a bitmap", (int)i + 1);
      return false;
    }
  }
  return true;
}

#ifndef _WIN32

bool bc_brand_supported(void)
{
  return false;
}

BC_BrandResult bc_brand_exe(const char *exe_path, const BC_Branding *b, char *err, size_t err_size)
{
  (void)exe_path;
  (void)b;
  snprintf(err, err_size, "executable branding is only available in Windows builds");
  return BC_BRAND_ERROR;
}

#else /* _WIN32 */

#  include <windows.h>

/* Explicit wide resource types: RT_* follow the UNICODE macro, these do not. */
#  define BC_RT_ICON MAKEINTRESOURCEW(3)
#  define BC_RT_GROUP_ICON MAKEINTRESOURCEW(14)
#  define BC_RT_VERSION MAKEINTRESOURCEW(16)
#  define BC_LANG_EN_US MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)
#  define BC_GROUP_ENTRY_SIZE 14
#  define BC_OLD_IDS_MAX 256

bool bc_brand_supported(void)
{
  return true;
}

/* -------------------------------------------------------------------------------------------- */
/* Version resource
 *
 * A tree of nodes: u16 wLength (the node with its children), u16 wValueLength (bytes for binary
 * values, UTF-16 units for text), u16 wType (0 binary, 1 text), UTF-16 key, padding to 4 bytes,
 * value, then the children, each starting on a 4 byte boundary. */

typedef struct BC_Buffer {
  uint8_t data[16384]; /* 8 strings of at most 256 UTF-16 units: under 6 KiB. */
  size_t size;
  bool ok;
} BC_Buffer;

static void bc_put(BC_Buffer *b, const void *src, const size_t n)
{
  if (!b->ok || n > sizeof(b->data) - b->size) {
    b->ok = false;
    return;
  }
  memcpy(b->data + b->size, src, n);
  b->size += n;
}

static void bc_align(BC_Buffer *b)
{
  static const uint8_t zero[4] = {0};
  bc_put(b, zero, (4 - b->size % 4) % 4);
}

static size_t bc_node_begin(BC_Buffer *b, const wchar_t *key, const size_t value_length, const uint16_t type)
{
  bc_align(b);
  const size_t start = b->size;
  const uint16_t header[3] = {0, (uint16_t)value_length, type};
  bc_put(b, header, sizeof(header));
  bc_put(b, key, (wcslen(key) + 1) * sizeof(wchar_t));
  bc_align(b);
  return start;
}

static void bc_node_end(BC_Buffer *b, const size_t start)
{
  if (b->ok) {
    const uint16_t length = (uint16_t)(b->size - start);
    memcpy(b->data + start, &length, sizeof(length));
  }
}

/** Text value; empty values are left out, as rc.exe users usually do. */
static void bc_string(BC_Buffer *b, const wchar_t *key, const char *utf8)
{
  if (utf8 == NULL || utf8[0] == '\0') {
    return;
  }
  wchar_t *value = bc_utf16(utf8);
  if (value == NULL) {
    b->ok = false;
    return;
  }
  const size_t units = wcslen(value) + 1;
  const size_t start = bc_node_begin(b, key, units, 1);
  bc_put(b, value, units * sizeof(wchar_t));
  bc_node_end(b, start);
  free(value);
}

static bool bc_version_resource(const BC_Branding *br, BC_Buffer *b)
{
  b->size = 0;
  b->ok = true;
  const uint16_t *v = br->version;
  char version[32];
  snprintf(version, sizeof(version), "%u.%u.%u.%u", v[0], v[1], v[2], v[3]);

  VS_FIXEDFILEINFO fixed;
  memset(&fixed, 0, sizeof(fixed));
  fixed.dwSignature = 0xFEEF04BD;
  fixed.dwStrucVersion = 0x00010000;
  fixed.dwFileVersionMS = fixed.dwProductVersionMS = ((DWORD)v[0] << 16) | v[1];
  fixed.dwFileVersionLS = fixed.dwProductVersionLS = ((DWORD)v[2] << 16) | v[3];
  fixed.dwFileFlagsMask = VS_FFI_FILEFLAGSMASK;
  fixed.dwFileOS = VOS_NT_WINDOWS32;
  fixed.dwFileType = VFT_APP;

  const size_t root = bc_node_begin(b, L"VS_VERSION_INFO", sizeof(fixed), 0);
  bc_put(b, &fixed, sizeof(fixed));
  const size_t file_info = bc_node_begin(b, L"StringFileInfo", 0, 1);
  /* U.S. English, UTF-16 code page: must match the Translation value below. */
  const size_t table = bc_node_begin(b, L"040904B0", 0, 1);
  bc_string(b, L"CompanyName", br->company);
  bc_string(b, L"FileDescription", br->product);
  bc_string(b, L"FileVersion", version);
  bc_string(b, L"InternalName", br->product);
  bc_string(b, L"LegalCopyright", br->copyright);
  bc_string(b, L"OriginalFilename", br->original_filename);
  bc_string(b, L"ProductName", br->product);
  bc_string(b, L"ProductVersion", version);
  bc_node_end(b, table);
  bc_node_end(b, file_info);
  const size_t var_info = bc_node_begin(b, L"VarFileInfo", 0, 1);
  const size_t var = bc_node_begin(b, L"Translation", 4, 0);
  const uint16_t translation[2] = {0x0409, 1200};
  bc_put(b, translation, sizeof(translation));
  bc_node_end(b, var);
  bc_node_end(b, var_info);
  bc_node_end(b, root);
  return b->ok;
}

/* -------------------------------------------------------------------------------------------- */
/* Current resources */

typedef struct BC_Current {
  bool has_group;
  WORD group_lang;
  WORD old_ids[BC_OLD_IDS_MAX];
  int old_count;
  bool group_matches;
  WORD max_icon_id;

  bool has_version;
  WORD version_id;
  WORD version_lang;
  bool version_matches;
} BC_Current;

static BOOL CALLBACK bc_on_group_lang(HMODULE m, LPCWSTR type, LPCWSTR name, WORD lang, LONG_PTR user)
{
  (void)m;
  (void)type;
  (void)name;
  BC_Current *c = (BC_Current *)user;
  c->has_group = true;
  c->group_lang = lang;
  return FALSE; /* The first language is the one GHOST and Explorer get on any system. */
}

static BOOL CALLBACK bc_on_icon(HMODULE m, LPCWSTR type, LPWSTR name, LONG_PTR user)
{
  (void)m;
  (void)type;
  BC_Current *c = (BC_Current *)user;
  if (IS_INTRESOURCE(name) && LOWORD((ULONG_PTR)name) > c->max_icon_id) {
    c->max_icon_id = LOWORD((ULONG_PTR)name);
  }
  return TRUE;
}

static BOOL CALLBACK bc_on_version(HMODULE m, LPCWSTR type, LPWSTR name, LONG_PTR user)
{
  (void)m;
  (void)type;
  BC_Current *c = (BC_Current *)user;
  if (!IS_INTRESOURCE(name)) {
    return TRUE;
  }
  c->has_version = true;
  c->version_id = LOWORD((ULONG_PTR)name);
  return FALSE;
}

static BOOL CALLBACK bc_on_version_lang(HMODULE m, LPCWSTR type, LPCWSTR name, WORD lang, LONG_PTR user)
{
  (void)m;
  (void)type;
  (void)name;
  ((BC_Current *)user)->version_lang = lang;
  return FALSE;
}

static const void *bc_find(HMODULE m, LPCWSTR type, LPCWSTR name, WORD lang, DWORD *r_size)
{
  HRSRC res = FindResourceExW(m, type, name, lang);
  HGLOBAL data = res ? LoadResource(m, res) : NULL;
  *r_size = res ? SizeofResource(m, res) : 0;
  return data ? LockResource(data) : NULL;
}

/** Read what the executable holds now and whether it already matches the branding. */
static bool bc_scan(const wchar_t *path, const BC_Branding *br, const BC_Buffer *version, BC_Current *c)
{
  memset(c, 0, sizeof(*c));
  HMODULE m = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
  if (m == NULL) {
    return false;
  }
  EnumResourceLanguagesW(m, BC_RT_GROUP_ICON, L"" BC_BRAND_ICON_GROUP, bc_on_group_lang, (LONG_PTR)c);
  EnumResourceNamesW(m, BC_RT_ICON, bc_on_icon, (LONG_PTR)c);
  EnumResourceNamesW(m, BC_RT_VERSION, bc_on_version, (LONG_PTR)c);

  DWORD size;
  const uint8_t *group = c->has_group ? (const uint8_t *)bc_find(m, BC_RT_GROUP_ICON, L"" BC_BRAND_ICON_GROUP, c->group_lang, &size) : NULL;
  if (group != NULL && size >= 6) {
    const int count = bc_ld16(group + 4);
    for (int i = 0; i < count && c->old_count < BC_OLD_IDS_MAX && 6 + (size_t)(i + 1) * BC_GROUP_ENTRY_SIZE <= size; i++) {
      c->old_ids[c->old_count++] = bc_ld16(group + 6 + i * BC_GROUP_ENTRY_SIZE + 12);
    }
    /* Same images in the same order: each group entry carries the .ico entry's first 12 bytes. */
    if (br->ico != NULL && count == bc_ld16(br->ico + 4) && c->old_count == count) {
      c->group_matches = true;
      for (int i = 0; i < count && c->group_matches; i++) {
        const uint8_t *entry = br->ico + 6 + 16 * i;
        DWORD image_size;
        const void *image = bc_find(m, BC_RT_ICON, MAKEINTRESOURCEW(c->old_ids[i]), c->group_lang, &image_size);
        c->group_matches = image != NULL &&
                           memcmp(group + 6 + i * BC_GROUP_ENTRY_SIZE, entry, 12) == 0 &&
                           image_size == bc_ld32(entry + 8) &&
                           memcmp(image, br->ico + bc_ld32(entry + 12), image_size) == 0;
      }
    }
  }

  if (c->has_version) {
    c->version_lang = BC_LANG_EN_US;
    EnumResourceLanguagesW(m, BC_RT_VERSION, MAKEINTRESOURCEW(c->version_id), bc_on_version_lang, (LONG_PTR)c);
    const void *current = bc_find(m, BC_RT_VERSION, MAKEINTRESOURCEW(c->version_id), c->version_lang, &size);
    c->version_matches = current != NULL && size == version->size && memcmp(current, version->data, size) == 0;
  }
  FreeLibrary(m);
  return true;
}

/* -------------------------------------------------------------------------------------------- */
/* Update */

static bool bc_apply(const wchar_t *path, const BC_Branding *br, const BC_Current *c, const BC_Buffer *version)
{
  HANDLE h = BeginUpdateResourceW(path, FALSE);
  if (h == NULL) {
    return false;
  }
  BOOL ok = TRUE;
  if (br->ico != NULL && !c->group_matches) {
    const WORD lang = c->has_group ? c->group_lang : BC_LANG_EN_US;
    const int count = bc_ld16(br->ico + 4);
    uint8_t group[6 + BC_BRAND_ICO_MAX_IMAGES * BC_GROUP_ENTRY_SIZE];
    memcpy(group, br->ico, 6);
    /* Reuse the old images' IDs: overwriting works everywhere, while deleting is ignored by some
     * implementations (Wine). Extra images get IDs above every existing one, so no other icon
     * group (the player's .blend file icon) is ever touched. */
    DWORD next_id = c->max_icon_id;
    for (int i = 0; i < count && ok; i++) {
      const uint8_t *entry = br->ico + 6 + 16 * i;
      uint8_t *g = group + 6 + i * BC_GROUP_ENTRY_SIZE;
      const DWORD id = i < c->old_count ? c->old_ids[i] : ++next_id;
      if (id > 0xFFFF) {
        ok = FALSE;
        break;
      }
      memcpy(g, entry, 12);
      g[12] = (uint8_t)id;
      g[13] = (uint8_t)(id >> 8);
      ok = UpdateResourceW(h, BC_RT_ICON, MAKEINTRESOURCEW(id), lang, (void *)(br->ico + bc_ld32(entry + 12)), bc_ld32(entry + 8));
    }
    for (int i = count; i < c->old_count && ok; i++) {
      ok = UpdateResourceW(h, BC_RT_ICON, MAKEINTRESOURCEW(c->old_ids[i]), lang, NULL, 0);
    }
    ok = ok && UpdateResourceW(h, BC_RT_GROUP_ICON, L"" BC_BRAND_ICON_GROUP, lang, group, (DWORD)(6 + count * BC_GROUP_ENTRY_SIZE));
  }
  if (ok && !c->version_matches) {
    ok = UpdateResourceW(h,
                         BC_RT_VERSION,
                         MAKEINTRESOURCEW(c->has_version ? c->version_id : 1),
                         c->has_version ? c->version_lang : BC_LANG_EN_US,
                         (void *)version->data,
                         (DWORD)version->size);
  }
  /* Discard everything when one update failed: never half branded. */
  return EndUpdateResourceW(h, !ok) && ok;
}

BC_BrandResult bc_brand_exe(const char *exe_path, const BC_Branding *b, char *err, size_t err_size)
{
  BC_BrandResult result = BC_BRAND_ERROR;
  BC_Buffer *version = (BC_Buffer *)malloc(sizeof(BC_Buffer));
  char tmp_path[BC_PATH_MAX + 16];
  snprintf(tmp_path, sizeof(tmp_path), "%s.brand.tmp", exe_path);
  wchar_t *wpath = bc_utf16(exe_path);
  wchar_t *wtmp = bc_utf16(tmp_path);
  BC_Current current;

  if (version == NULL || wpath == NULL || wtmp == NULL || !bc_version_resource(b, version)) {
    snprintf(err, err_size, "invalid version information (texts must be valid UTF-8)");
  }
  else if (!bc_scan(wpath, b, version, &current)) {
    snprintf(err, err_size, "cannot read the resources of '%s' (error %lu)", exe_path, GetLastError());
  }
  else if ((b->ico == NULL || current.group_matches) && current.version_matches) {
    result = BC_BRAND_UNCHANGED;
  }
  /* Work on a copy and swap it in: an interrupted update never leaves a broken executable. */
  else if (!CopyFileW(wpath, wtmp, FALSE) || !bc_apply(wtmp, b, &current, version) ||
           !MoveFileExW(wtmp, wpath, MOVEFILE_REPLACE_EXISTING))
  {
    snprintf(err, err_size, "cannot update the resources of '%s' (error %lu)", exe_path, GetLastError());
    DeleteFileW(wtmp);
  }
  else {
    result = BC_BRAND_CHANGED;
  }
  free(version);
  free(wpath);
  free(wtmp);
  return result;
}

#endif /* _WIN32 */
