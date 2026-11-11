# SPDX-License-Identifier: GPL-2.0-or-later
#
# End to end: bc_tool --batch -> game executable (launcher + embedded or external manifest) -> player in
# engine/, with a stand-in player that receives the key through the pipe contract and verifies
# the decrypted main file. bc_tool finds bc_launcher next to itself.
# Inputs: BC_TOOL, BC_PLAYER (bc_fake_player), BC_TESTS (writes a test icon, scans files for a
# key), BC_PROVIDER
# (bc_fake_provider), BC_EXE_SUFFIX, BC_MANIFEST_NAME (BINARYCRYPT_MANIFEST_FILENAME), BC_WORK,
# and BC_RUNNER (the cross compiling emulator, e.g. wine; empty for native builds).

cmake_minimum_required(VERSION 3.16)

function(bc_run expect_success)
  execute_process(COMMAND ${BC_RUNNER} ${ARGN}
                  RESULT_VARIABLE result
                  OUTPUT_VARIABLE out
                  ERROR_VARIABLE err)
  set(bc_last_output "${out}${err}" PARENT_SCOPE)
  if(expect_success AND NOT result EQUAL 0)
    message(FATAL_ERROR "expected success: ${ARGN}\nexit ${result}\n${out}${err}")
  endif()
  if(NOT expect_success AND result EQUAL 0)
    message(FATAL_ERROR "expected failure: ${ARGN}\n${out}${err}")
  endif()
endfunction()

function(bc_expect_output text)
  string(FIND "${bc_last_output}" "${text}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "expected output containing '${text}', got:\n${bc_last_output}")
  endif()
endfunction()

# Optional second argument: the kind byte (offset 11) as two hex digits, 00 .blend, 01 Python
# module, 02 data file.
function(bc_expect_sealed file)
  if(NOT EXISTS "${file}")
    message(FATAL_ERROR "missing ${file}")
  endif()
  # HEX mode: text mode reads are not byte exact on binary data. "UPBGEBC" 0x1A.
  file(READ "${file}" head LIMIT 8 HEX)
  if(NOT head STREQUAL "555042474542431a")
    message(FATAL_ERROR "${file} is not a BinaryCrypt container")
  endif()
  if(ARGC GREATER 1)
    file(READ "${file}" kind OFFSET 11 LIMIT 1 HEX)
    if(NOT kind STREQUAL "${ARGV1}")
      message(FATAL_ERROR "${file} holds kind ${kind}, expected ${ARGV1}")
    endif()
  endif()
endfunction()

file(REMOVE_RECURSE "${BC_WORK}")
set(SRC "${BC_WORK}/src")
set(DIST "${BC_WORK}/dist")
get_filename_component(player_name "${BC_PLAYER}" NAME)
set(game "My Game${BC_EXE_SUFFIX}")

# Stand-in sources: the real magic and ~200 KB of payload (several 64 KiB chunks).
string(REPEAT "game data 0123456789 " 9000 payload)
file(WRITE "${SRC}/game.blend" "BLENDER-v405${payload}")
file(WRITE "${SRC}/levels/level 1.blend" "BLENDER-v405 level one ${payload}")
file(WRITE "${SRC}/levels/notes.txt" "not a blend file")
file(WRITE "${SRC}/levels/logic.py" "SPEED = 3\n")
file(WRITE "${SRC}/levels/__init__.py" "")
file(WRITE "${SRC}/levels/stats.json" "{\"hp\": 10}")
file(COPY "${BC_PLAYER}" DESTINATION "${DIST}/engine")

# -- Export into the game folder --------------------------------------------------------------
file(WRITE "${BC_WORK}/game.bcproj"
  "version = 1\nsource_root = src\noutput_dir = dist\n"
  "game_name = My Game\nplayer = engine/${player_name}\nmain = src/game.blend\ninput = src\n"
  "data_extensions = json\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/game.bcproj")
# No key setting: a key for this project, created next to the project file.
bc_expect_output("Created the project key")
if(NOT EXISTS "${BC_WORK}/game.key")
  message(FATAL_ERROR "the project key file was not created next to the project")
endif()
bc_expect_sealed("${DIST}/game.blend" 00)
file(SHA256 "${DIST}/levels/level 1.blend" level_project)
bc_expect_sealed("${DIST}/levels/level 1.blend" 00)
# Python modules and the data extensions come with the folders, encrypted; empty files as they are.
bc_expect_sealed("${DIST}/levels/logic.py" 01)
bc_expect_sealed("${DIST}/levels/stats.json" 02)
file(SIZE "${DIST}/levels/__init__.py" init_size)
if(EXISTS "${DIST}/levels/notes.txt" OR NOT EXISTS "${DIST}/${game}" OR NOT init_size EQUAL 0)
  message(FATAL_ERROR "unexpected mirror output")
endif()
# The root holds only the game executable, the encrypted data and engine/.
file(GLOB root_entries RELATIVE "${DIST}" "${DIST}/*")
list(SORT root_entries)
if(NOT root_entries STREQUAL "${game};engine;game.blend;levels")
  message(FATAL_ERROR "unexpected game folder content: ${root_entries}")
endif()

set(ENV{BC_TEST_EXPECTED} "${SRC}/game.blend")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
# The player's window shows the game's name (a space in it survives the Windows command line).
bc_expect_output("in the window 'My Game', showing: nothing")
# A handle left inheritable by whoever starts the game (a store client, a script) must not reach
# the player: the launcher passes the key pipe and its standard streams, nothing else.
bc_run(TRUE "${BC_TESTS}" --spawn-leaking "${DIST}/${game}")
bc_expect_output("decrypted correctly")
# Integrity check (+ Python by default): a library added next to the player (a proxy DLL), a
# changed one, a .pth or a changed Python module stops the game. Bytecode is removed by the
# export, before every launch and after the player exits, so a test run leaves none to ship.
file(WRITE "${DIST}/engine/version.dll" "proxy")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("library, program or Python file")
file(REMOVE "${DIST}/engine/version.dll")
file(WRITE "${DIST}/engine/startup.pth" "import os")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("library, program or Python file")
file(REMOVE "${DIST}/engine/startup.pth")
set(pyc "${DIST}/engine/scripts/__pycache__/menu.cpython-311.pyc")
file(WRITE "${DIST}/engine/scripts/menu.py" "print()")
file(WRITE "${pyc}" "left by a test run")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/game.bcproj")
bc_expect_output("Native code and Python check")
if(EXISTS "${pyc}")
  message(FATAL_ERROR "the export left Python bytecode in the game folder")
endif()
file(WRITE "${pyc}" "written by the last run")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
if(EXISTS "${pyc}")
  message(FATAL_ERROR "the game executable left Python bytecode in the game folder")
endif()
file(WRITE "${DIST}/engine/scripts/menu.py" "print('patched')")
bc_run(FALSE "${DIST}/${game}")
file(WRITE "${DIST}/engine/scripts/menu.py" "print()")
bc_run(TRUE "${DIST}/${game}")
# An encrypted module swapped for a plain one (the player would import it) stops the game too.
file(RENAME "${DIST}/levels/logic.py" "${BC_WORK}/logic.py.sealed")
file(WRITE "${DIST}/levels/logic.py" "SPEED = 99\n")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("library, program or Python file")
file(REMOVE "${DIST}/levels/logic.py")
file(RENAME "${BC_WORK}/logic.py.sealed" "${DIST}/levels/logic.py")
bc_run(TRUE "${DIST}/${game}")
# Libraries level: Python sources, bytecode and .pth files are not covered.
file(READ "${BC_WORK}/game.bcproj" checked)
file(WRITE "${BC_WORK}/native.bcproj" "${checked}integrity = native\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/native.bcproj")
bc_expect_output("Native code check")
file(WRITE "${DIST}/engine/__pycache__/bge.cpython-311.pyc" "bytecode")
file(WRITE "${DIST}/engine/startup.pth" "import os")
file(WRITE "${DIST}/engine/scripts/menu.py" "print('patched')")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
file(WRITE "${DIST}/engine/version.dll" "proxy")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("was changed, added or removed")
file(REMOVE "${DIST}/engine/version.dll")
file(REMOVE_RECURSE "${DIST}/engine/__pycache__" "${DIST}/engine/scripts")
file(REMOVE "${DIST}/engine/startup.pth")
# Debug displays reach the player as -g options, nothing else (none by default, see above).
file(WRITE "${BC_WORK}/shows.bcproj" "${checked}show_framerate = 1\nshow_physics = 1\nshow_console = 1\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/shows.bcproj")
bc_expect_output("The game shows a console, the frame rate, the physics shapes")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("showing: show_framerate show_physics")
# Player level: only the player.
file(WRITE "${BC_WORK}/unchecked.bcproj" "${checked}integrity = player\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/unchecked.bcproj")
file(WRITE "${DIST}/engine/version.dll" "proxy")
bc_run(TRUE "${DIST}/${game}")
file(REMOVE "${DIST}/engine/version.dll")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/game.bcproj")
bc_expect_output("Native code and Python check")
# Every 32 byte window of the game executable tried as the key: none is (it is stored masked).
bc_run(TRUE "${BC_TESTS}" --find-key "${DIST}/${game}" "${DIST}/game.blend")
bc_expect_output("key not found")

# Command line arguments never reach the player (the stand-in fails on any extra argument).
bc_run(TRUE "${DIST}/${game}" -p evil.py)

# The game executable keeps working when renamed or moved with its folder.
file(RENAME "${DIST}/${game}" "${DIST}/renamed${BC_EXE_SUFFIX}")
bc_run(TRUE "${DIST}/renamed${BC_EXE_SUFFIX}")
bc_expect_output("in the window 'renamed'")
file(RENAME "${DIST}/renamed${BC_EXE_SUFFIX}" "${DIST}/${game}")

# A modified player is refused before it gets the key.
file(APPEND "${DIST}/engine/${player_name}" "patched")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("modified or replaced")
file(REMOVE "${DIST}/engine/${player_name}")
file(COPY "${BC_PLAYER}" DESTINATION "${DIST}/engine")
bc_run(TRUE "${DIST}/${game}")

# Data appended after the embedded manifest hides it: refused, nothing runs.
file(APPEND "${DIST}/${game}" "x")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("carries no game")

# Re-running replaces everything atomically: valid again, no temporary file left behind.
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/game.bcproj")
bc_run(TRUE "${DIST}/${game}")
file(GLOB_RECURSE leftovers "${DIST}/*.tmp")
if(leftovers)
  message(FATAL_ERROR "temporary files left: ${leftovers}")
endif()

# -- External manifest ------------------------------------------------------------------------
# The game executable is the launcher byte for byte (a signature on bc_launcher stays valid) and
# the manifest sits next to it.
get_filename_component(tool_dir "${BC_TOOL}" DIRECTORY)
file(READ "${BC_WORK}/game.bcproj" project)
file(WRITE "${BC_WORK}/external.bcproj" "${project}manifest = external\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/external.bcproj")
file(GLOB root_entries RELATIVE "${DIST}" "${DIST}/*")
list(SORT root_entries)
set(expected_entries "${game};${BC_MANIFEST_NAME};engine;game.blend;levels")
list(SORT expected_entries)
if(NOT root_entries STREQUAL expected_entries)
  message(FATAL_ERROR "unexpected external manifest game folder: ${root_entries}")
endif()
file(SHA256 "${DIST}/${game}" game_hash)
file(SHA256 "${tool_dir}/bc_launcher${BC_EXE_SUFFIX}" launcher_hash)
if(NOT game_hash STREQUAL launcher_hash)
  message(FATAL_ERROR "external mode changed the launcher bytes")
endif()
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
file(RENAME "${DIST}/${BC_MANIFEST_NAME}" "${BC_WORK}/saved.manifest")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("no ${BC_MANIFEST_NAME}")
file(WRITE "${DIST}/${BC_MANIFEST_NAME}" "UPBGEBCM forged")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("manifest is corrupt")
file(RENAME "${BC_WORK}/saved.manifest" "${DIST}/${BC_MANIFEST_NAME}")
bc_run(TRUE "${DIST}/${game}")
# Back to embedded: the stale manifest file is removed.
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/game.bcproj")
if(EXISTS "${DIST}/${BC_MANIFEST_NAME}")
  message(FATAL_ERROR "embedded export left the old ${BC_MANIFEST_NAME}")
endif()
bc_run(TRUE "${DIST}/${game}")

# -- Windows branding -------------------------------------------------------------------------
# The player is branded before it is hashed, so the game still starts; an already branded player
# is left untouched by the next export.
if(BC_EXE_SUFFIX STREQUAL ".exe")
  bc_run(TRUE "${BC_TESTS}" --write-ico "${BC_WORK}/game.ico")
  file(WRITE "${BC_WORK}/branded.bcproj"
    "${project}icon = game.ico\ngame_version = 2.1\ncompany = Test Studio\n")
  bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/branded.bcproj")
  bc_expect_output("Player icon and version information updated")
  bc_run(TRUE "${DIST}/${game}")
  bc_expect_output("decrypted correctly")
  file(SHA256 "${DIST}/engine/${player_name}" branded_hash)
  bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/branded.bcproj")
  file(SHA256 "${DIST}/engine/${player_name}" again_hash)
  string(FIND "${bc_last_output}" "information updated" updated_again)
  if(NOT branded_hash STREQUAL again_hash OR NOT updated_again EQUAL -1)
    message(FATAL_ERROR "an already branded player was rewritten")
  endif()
  bc_run(TRUE "${DIST}/${game}")
  bc_expect_output("decrypted correctly")
  file(GLOB_RECURSE leftovers "${DIST}/*.tmp")
  if(leftovers)
    message(FATAL_ERROR "temporary files left: ${leftovers}")
  endif()
endif()

# -- Online key -------------------------------------------------------------------------------
# The content key is created on the first export, kept out of the game folder, and reaches the
# player only through the provider and an envelope sealed for the launch.
get_filename_component(provider_name "${BC_PROVIDER}" NAME)
file(COPY "${BC_PROVIDER}" DESTINATION "${DIST}/engine")
set(online_settings "key = online\nkey_file = content.key\nkey_provider = engine/${provider_name}\nkey_url = https://keys.example.com/key\n")
file(WRITE "${BC_WORK}/online.bcproj" "${project}${online_settings}")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/online.bcproj")
bc_expect_output("Created the content key")
if(NOT EXISTS "${BC_WORK}/content.key")
  message(FATAL_ERROR "the content key file was not created")
endif()
set(ENV{BC_TEST_PROVIDER_KEY_FILE} "${BC_WORK}/content.key")
set(ENV{BC_TEST_PROVIDER_EXPECT_URL} "https://keys.example.com/key")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/online.bcproj")
string(FIND "${bc_last_output}" "Created the content key" created_again)
if(NOT created_again EQUAL -1)
  message(FATAL_ERROR "the existing content key was replaced")
endif()
# The game executable's arguments reach the provider (store login tokens), not the player.
set(ENV{BC_TEST_PROVIDER_EXPECT_ARG} "-AUTH_PASSWORD=abc")
bc_run(TRUE "${DIST}/${game}" -AUTH_PASSWORD=abc)
set(ENV{BC_TEST_PROVIDER_EXPECT_ARG} "")
# Provider failures reach the player with the provider's own message.
set(ENV{BC_TEST_PROVIDER_MODE} "fail")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("test provider refused")
set(ENV{BC_TEST_PROVIDER_MODE} "silent")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("Store API init failed")
set(ENV{BC_TEST_PROVIDER_MODE} "garbage")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("not valid for this launch")
set(ENV{BC_TEST_PROVIDER_MODE} "noise")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
set(ENV{BC_TEST_PROVIDER_MODE} "ok")
# A server answering with another game's key is caught by the key id.
file(WRITE "${BC_WORK}/other.key" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")
set(ENV{BC_TEST_PROVIDER_KEY_FILE} "${BC_WORK}/other.key")
set(ENV{BC_TEST_PROVIDER_MODE} "wrongkey")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("key of another game")
set(ENV{BC_TEST_PROVIDER_MODE} "ok")
set(ENV{BC_TEST_PROVIDER_KEY_FILE} "${BC_WORK}/content.key")
# Permanent cache: online once, then the provider is not needed any more.
set(ENV{XDG_CACHE_HOME} "${BC_WORK}/cache")
file(WRITE "${BC_WORK}/cached.bcproj" "${project}${online_settings}key_cache = permanent\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/cached.bcproj")
bc_run(TRUE "${DIST}/${game}")
set(ENV{BC_TEST_PROVIDER_MODE} "fail")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
# Without the cache option a cached key is never used.
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/online.bcproj")
bc_run(FALSE "${DIST}/${game}")
bc_expect_output("test provider refused")
set(ENV{BC_TEST_PROVIDER_MODE} "ok")
# Key per update: update 2 changes the main file; the game then needs two keys (the player picks
# the main file's by key id), the unchanged level, module and data file keep their bytes (the empty
# __init__.py uses no key), and a cached key is not asked for again.
set(ENV{BC_TEST_PROVIDER_KEY_FILE} "${BC_WORK}/updates.key")
set(ENV{BC_TEST_PROVIDER_LOG} "${BC_WORK}/provider.log")
set(rotation "key = online\nkey_file = updates.key\nkey_provider = engine/${provider_name}\nkey_url = https://keys.example.com/key\nkey_cache = permanent\nkey_rotation = per_update\n")
file(WRITE "${BC_WORK}/update1.bcproj" "${project}${rotation}key_update = 1\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/update1.bcproj")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
file(SHA256 "${DIST}/game.blend" main_v1)
file(SHA256 "${DIST}/levels/level 1.blend" level_v1)
file(APPEND "${SRC}/game.blend" "new content of update 2")
file(WRITE "${BC_WORK}/update2.bcproj" "${project}${rotation}key_update = 2\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/update2.bcproj")
bc_expect_output("New key for update 2")
bc_expect_output("1 file(s) with its key, 3 unchanged with earlier keys; the game uses 2 key(s)")
file(SHA256 "${DIST}/game.blend" main_v2)
file(SHA256 "${DIST}/levels/level 1.blend" level_v2)
if(main_v1 STREQUAL main_v2 OR NOT level_v1 STREQUAL level_v2)
  message(FATAL_ERROR "update 2 must rewrite the changed main file only")
endif()
file(REMOVE "${BC_WORK}/provider.log")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
bc_expect_output("2 key(s)")
file(STRINGS "${BC_WORK}/provider.log" requests)
list(LENGTH requests request_count)
string(FIND "${requests}" "," comma)
if(NOT request_count EQUAL 1 OR NOT comma EQUAL -1)
  message(FATAL_ERROR "only the key of update 2 should be asked for (update 1 is cached): ${requests}")
endif()
# Without the cache both keys come in one request.
string(REPLACE "key_cache = permanent\n" "" uncached "${project}${rotation}key_update = 2\nkey_cache = none\n")
file(WRITE "${BC_WORK}/update2_online.bcproj" "${uncached}")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/update2_online.bcproj")
file(REMOVE "${BC_WORK}/provider.log")
bc_run(TRUE "${DIST}/${game}")
file(STRINGS "${BC_WORK}/provider.log" requests)
string(FIND "${requests}" "," comma)
if(comma EQUAL -1)
  message(FATAL_ERROR "both keys should be asked for in one request: ${requests}")
endif()
set(ENV{BC_TEST_PROVIDER_LOG} "")
set(ENV{BC_TEST_PROVIDER_KEY_FILE} "${BC_WORK}/content.key")

# A key file inside the game folder would ship with the game: refused.
file(WRITE "${BC_WORK}/leaky.bcproj" "${project}key = online\nkey_file = dist/content.key\nkey_provider = engine/${provider_name}\n")
bc_run(FALSE "${BC_TOOL}" --batch "${BC_WORK}/leaky.bcproj")
bc_expect_output("inside the game folder")
file(WRITE "${BC_WORK}/leaky_project.bcproj" "${project}key_file = dist/game.key\n")
bc_run(FALSE "${BC_TOOL}" --batch "${BC_WORK}/leaky_project.bcproj")
bc_expect_output("inside the game folder")

# -- Build key --------------------------------------------------------------------------------
# The key built into bc_tool and the launcher: stored as two shares, so neither executable holds
# it in one piece.
get_filename_component(tool_name "${BC_TOOL}" NAME)
file(WRITE "${BC_WORK}/build.bcproj" "${project}key = build\n")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/build.bcproj")
bc_run(TRUE "${DIST}/${game}")
bc_expect_output("decrypted correctly")
foreach(binary "${DIST}/${game}" "${tool_dir}/${tool_name}")
  bc_run(TRUE "${BC_TESTS}" --find-key "${binary}" "${DIST}/game.blend")
  bc_expect_output("key not found")
endforeach()

# Back to the project key for the scenarios below: the same key as before, the same files.
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/game.bcproj")
string(FIND "${bc_last_output}" "Created the project key" created_again)
file(SHA256 "${DIST}/levels/level 1.blend" level_again)
if(NOT created_again EQUAL -1 OR NOT level_again STREQUAL level_project)
  message(FATAL_ERROR "the existing project key was not reused")
endif()

# A missing player is reported by the tool, not discovered by players of the game.
file(WRITE "${BC_WORK}/broken.bcproj"
  "version = 1\nsource_root = src\noutput_dir = dist\n"
  "player = engine/nothing_here\nmain = src/game.blend\ninput = src\n")
bc_run(FALSE "${BC_TOOL}" --batch "${BC_WORK}/broken.bcproj")
bc_expect_output("Player not found")

# -- Output folder ----------------------------------------------------------------------------
# Always another folder than the sources, which stay untouched; the source folder itself, or one
# around it, is refused. No game_name: the executable is named after the main file.
set(project_tail "player = engine/${player_name}\nmain = src/game.blend\ninput = src\n")
file(WRITE "${BC_WORK}/same.bcproj" "version = 1\nsource_root = src\noutput_dir = src\n${project_tail}")
bc_run(FALSE "${BC_TOOL}" --batch "${BC_WORK}/same.bcproj")
bc_expect_output("must not be, or contain, the source folder")
file(WRITE "${BC_WORK}/around.bcproj" "version = 1\nsource_root = src\noutput_dir = .\n${project_tail}")
bc_run(FALSE "${BC_TOOL}" --batch "${BC_WORK}/around.bcproj")
bc_expect_output("must not be, or contain, the source folder")
file(COPY "${BC_PLAYER}" DESTINATION "${BC_WORK}/dist2/engine")
file(WRITE "${BC_WORK}/default_name.bcproj" "version = 1\nsource_root = src\noutput_dir = dist2\n${project_tail}")
bc_run(TRUE "${BC_TOOL}" --batch "${BC_WORK}/default_name.bcproj")
file(READ "${SRC}/game.blend" head LIMIT 7 HEX)
if(NOT head STREQUAL "424c454e444552")
  message(FATAL_ERROR "the export modified a source file")
endif()
bc_run(TRUE "${BC_WORK}/dist2/game${BC_EXE_SUFFIX}")
bc_expect_output("decrypted correctly")

message(STATUS "end to end: all scenarios passed")
