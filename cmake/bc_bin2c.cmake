# SPDX-License-Identifier: GPL-2.0-or-later

# Embed a file in a C header, at build time, with no host tool (works when cross compiling):
#   cmake -DIN=<file> -DOUT=<header> -DNAME=<symbol> -P bc_bin2c.cmake
# The header defines `static const unsigned char NAME[]` and `static const int NAME_size`.

file(READ "${IN}" hex HEX)
string(LENGTH "${hex}" length)
math(EXPR size "${length} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex}")
# 16 bytes per line: some compilers limit the length of a source line.
string(REPEAT "0x[0-9a-f][0-9a-f]," 16 line)
string(REGEX REPLACE "(${line})" "\\1\n" bytes "${bytes}")
get_filename_component(source "${IN}" NAME)
file(WRITE "${OUT}.tmp"
  "/* Generated from ${source} by cmake/bc_bin2c.cmake. */\n"
  "static const unsigned char ${NAME}[${size}] = {\n${bytes}};\n"
  "static const int ${NAME}_size = ${size};\n")
file(RENAME "${OUT}.tmp" "${OUT}")
