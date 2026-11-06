/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "bc_embed.h"

#include <stdlib.h>
#include <string.h>

#include "bc_platform.h"

/* 64-bit file offsets: a launcher is small, but its position API must not truncate. */
#ifdef _WIN32
#  define bc_fseek _fseeki64
#  define bc_ftell _ftelli64
#else
#  define bc_fseek fseeko
#  define bc_ftell ftello
#endif

static bool bc_read_at(FILE *f, const uint64_t offset, void *dst, const size_t size)
{
  return bc_fseek(f, (int64_t)offset, SEEK_SET) == 0 && fread(dst, 1, size, f) == size;
}

static uint32_t bc_load_u32(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void bc_store_u32(uint8_t *p, const uint32_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

/**
 * End of the data we wrote: the file size, or for a signed PE executable the start of its
 * Authenticode table (the security data directory, whose "address" is a plain file offset). Pure
 * format parsing, so it works on any host and the tests run it everywhere.
 */
static uint64_t bc_logical_end(FILE *f, const uint64_t file_size)
{
  uint8_t dos[64];
  if (file_size < sizeof(dos) || !bc_read_at(f, 0, dos, sizeof(dos)) || dos[0] != 'M' ||
      dos[1] != 'Z')
  {
    return file_size;
  }
  const uint64_t pe = bc_load_u32(dos + 0x3c);
  uint8_t header[24 + 112 + 5 * 8];
  if (pe + sizeof(header) > file_size || !bc_read_at(f, pe, header, sizeof(header)) ||
      memcmp(header, "PE\0\0", 4) != 0)
  {
    return file_size;
  }
  /* Optional header right after the 4 byte signature and the 20 byte COFF header. */
  const uint8_t *optional = header + 24;
  const uint16_t magic = (uint16_t)(optional[0] | (optional[1] << 8));
  const size_t directories = magic == 0x20b ? 112 : magic == 0x10b ? 96 : 0;
  if (directories == 0 || bc_load_u32(optional + directories - 4) <= 4) {
    return file_size; /* Unknown optional header, or no security directory entry. */
  }
  const uint8_t *security = optional + directories + 4 * 8;
  const uint64_t table_offset = bc_load_u32(security);
  const uint64_t table_size = bc_load_u32(security + 4);
  if (table_size != 0 && table_offset + table_size == file_size) {
    return table_offset;
  }
  return file_size;
}

bool bc_exe_has_signature(const char *path)
{
  uint64_t size;
  FILE *f = bc_fopen(path, "rb");
  const bool is_signed = f != NULL && bc_file_size(path, &size) && bc_logical_end(f, size) != size;
  if (f != NULL) {
    fclose(f);
  }
  return is_signed;
}

bool bc_embed_write(const char *launcher_path,
                    const char *out_path,
                    const BC_Manifest *m,
                    const uint8_t key[BC_KEY_SIZE],
                    char *err,
                    size_t err_size)
{
  uint8_t manifest[BC_MANIFEST_MAX_SIZE];
  const size_t manifest_size = m ? bc_manifest_encode(m, key, manifest) : 0;
  if (m != NULL && manifest_size == 0) {
    snprintf(err, err_size, "invalid player or main file path");
    return false;
  }

  uint64_t launcher_size;
  uint8_t *launcher = NULL;
  FILE *in = bc_fopen(launcher_path, "rb");
  if (in == NULL || !bc_file_size(launcher_path, &launcher_size) ||
      (launcher = (uint8_t *)malloc((size_t)launcher_size + 1)) == NULL ||
      fread(launcher, 1, (size_t)launcher_size, in) != launcher_size)
  {
    if (in != NULL) {
      fclose(in);
    }
    free(launcher);
    snprintf(err, err_size, "cannot read the launcher '%s'", launcher_path);
    return false;
  }
  fclose(in);

  const size_t unaligned = (size_t)((launcher_size + manifest_size + BC_EMBED_TRAILER_SIZE) %
                                    BC_EMBED_ALIGNMENT);
  const size_t padding = unaligned ? BC_EMBED_ALIGNMENT - unaligned : 0;
  /* External manifest: nothing appended, the copy stays byte-identical (signature intact). */
  const size_t tail_size = m ? padding + BC_EMBED_TRAILER_SIZE : 0;
  uint8_t tail[BC_EMBED_ALIGNMENT + BC_EMBED_TRAILER_SIZE] = {0};
  bc_store_u32(tail + padding, (uint32_t)manifest_size);
  bc_store_u32(tail + padding + 4, (uint32_t)padding);
  memcpy(tail + padding + 8, BC_EMBED_MAGIC, 8);

  char tmp_path[BC_PATH_MAX + 8];
  const int tmp_len = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", out_path);
  FILE *out = (tmp_len > 0 && (size_t)tmp_len < sizeof(tmp_path)) ? bc_fopen(tmp_path, "wb") :
                                                                       NULL;
  bool ok = out != NULL;
  ok = ok && fwrite(launcher, 1, (size_t)launcher_size, out) == launcher_size;
  ok = ok && fwrite(manifest, 1, manifest_size, out) == manifest_size;
  ok = ok && fwrite(tail, 1, tail_size, out) == tail_size;
  free(launcher);
  if (out != NULL && fclose(out) != 0) {
    ok = false;
  }
  ok = ok && bc_make_executable(tmp_path) && bc_rename_replace(tmp_path, out_path);
  if (!ok) {
    if (out != NULL) {
      bc_remove(tmp_path);
    }
    snprintf(err, err_size, "cannot write the game executable '%s'", out_path);
  }
  return ok;
}

BC_ManifestResult bc_embed_read(const char *exe_path,
                                const uint8_t key[BC_KEY_SIZE],
                                BC_Manifest *r_manifest)
{
  uint64_t file_size;
  FILE *f = bc_fopen(exe_path, "rb");
  if (f == NULL || !bc_file_size(exe_path, &file_size)) {
    if (f != NULL) {
      fclose(f);
    }
    return BC_MANIFEST_IO_ERROR;
  }
  const uint64_t end = bc_logical_end(f, file_size);
  uint8_t trailer[BC_EMBED_TRAILER_SIZE];
  if (end < BC_EMBED_TRAILER_SIZE ||
      !bc_read_at(f, end - BC_EMBED_TRAILER_SIZE, trailer, sizeof(trailer)) ||
      memcmp(trailer + 8, BC_EMBED_MAGIC, 8) != 0)
  {
    fclose(f);
    return BC_MANIFEST_MISSING;
  }
  const uint64_t manifest_size = bc_load_u32(trailer);
  const uint64_t padding = bc_load_u32(trailer + 4);
  uint8_t manifest[BC_MANIFEST_MAX_SIZE];
  if (manifest_size > BC_MANIFEST_MAX_SIZE || padding >= BC_EMBED_ALIGNMENT ||
      end < BC_EMBED_TRAILER_SIZE + padding + manifest_size ||
      !bc_read_at(f,
                  end - BC_EMBED_TRAILER_SIZE - padding - manifest_size,
                  manifest,
                  (size_t)manifest_size))
  {
    fclose(f);
    return BC_MANIFEST_BAD_FORMAT;
  }
  fclose(f);
  return bc_manifest_decode(manifest, (size_t)manifest_size, key, r_manifest);
}

bool bc_manifest_file_write(const char *path,
                            const BC_Manifest *m,
                            const uint8_t key[BC_KEY_SIZE],
                            char *err,
                            size_t err_size)
{
  uint8_t manifest[BC_MANIFEST_MAX_SIZE];
  const size_t size = bc_manifest_encode(m, key, manifest);
  char tmp_path[BC_PATH_MAX + 8];
  const int tmp_len = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  FILE *f = (size != 0 && tmp_len > 0 && (size_t)tmp_len < sizeof(tmp_path)) ?
                bc_fopen(tmp_path, "wb") :
                NULL;
  bool ok = f != NULL && fwrite(manifest, 1, size, f) == size;
  if (f != NULL && fclose(f) != 0) {
    ok = false;
  }
  ok = ok && bc_rename_replace(tmp_path, path);
  if (!ok) {
    if (f != NULL) {
      bc_remove(tmp_path);
    }
    snprintf(err, err_size, "cannot write the manifest '%s'", path);
  }
  return ok;
}

BC_ManifestResult bc_manifest_file_read(const char *path,
                                        const uint8_t key[BC_KEY_SIZE],
                                        BC_Manifest *r_manifest)
{
  if (!bc_is_file(path)) {
    return BC_MANIFEST_MISSING;
  }
  uint8_t manifest[BC_MANIFEST_MAX_SIZE + 1];
  FILE *f = bc_fopen(path, "rb");
  if (f == NULL) {
    return BC_MANIFEST_IO_ERROR;
  }
  const size_t size = fread(manifest, 1, sizeof(manifest), f);
  fclose(f);
  if (size > BC_MANIFEST_MAX_SIZE) {
    return BC_MANIFEST_BAD_FORMAT;
  }
  return bc_manifest_decode(manifest, size, key, r_manifest);
}
