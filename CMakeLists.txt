# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.16)
project(UPBGE_BinaryCrypt C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

option(BINARYCRYPT_BUILD_GUI "Build the bc_tool editor (raylib + raygui). OFF: command line only" ON)
option(BINARYCRYPT_FETCH_RAYLIB "Download and build raylib 5.5 when no installed raylib is found" ON)
set(BINARYCRYPT_KEY_FILE "" CACHE FILEPATH
  "File holding a fixed key (64 hex digits, see bc_tool --export-key). Empty: random key per clean build")

if(MSVC)
  set(BC_WARNINGS /W4)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
  set(BC_WARNINGS -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes)
endif()

# ---------------------------------------------------------------------------------------------
# Core

add_library(monocypher STATIC common/monocypher/monocypher.c)
target_include_directories(monocypher PUBLIC common/monocypher)

# Everything except the key: shared by the key generator, the tool, the launcher and the tests.
add_library(bc_core STATIC
  common/bc_brand.c
  common/bc_embed.c
  common/bc_envelope.c
  common/bc_job.c
  common/bc_key_hex.c
  common/bc_keyring.c
  common/bc_manifest.c
  common/bc_native.c
  common/bc_platform.c
  common/bc_project.c
  common/bc_seal.c
)
target_include_directories(bc_core PUBLIC common)
target_link_libraries(bc_core PUBLIC monocypher)
target_compile_options(bc_core PRIVATE ${BC_WARNINGS})
if(WIN32)
  target_link_libraries(bc_core PUBLIC bcrypt)
endif()

# ---------------------------------------------------------------------------------------------
# Build key
#
# Generated while building, never at configure time: it does not appear in compile flags,
# compile_commands.json or any log. Random mode has no dependency, so the key only changes on a
# clean build (or when the header is deleted); reconfiguring or updating the sources keeps it.

add_executable(bc_keygen keygen/bc_keygen.c)
target_link_libraries(bc_keygen PRIVATE bc_core)
target_compile_options(bc_keygen PRIVATE ${BC_WARNINGS})

# The generator runs on the build machine: when cross compiling (for example Windows binaries
# from a Linux CI), point this to a bc_keygen built for the host.
set(BINARYCRYPT_HOST_KEYGEN "" CACHE FILEPATH "Host bc_keygen executable, required when cross compiling")
if(BINARYCRYPT_HOST_KEYGEN)
  set(BC_KEYGEN ${BINARYCRYPT_HOST_KEYGEN})
elseif(CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "Cross compiling: set BINARYCRYPT_HOST_KEYGEN to a bc_keygen built for this machine")
else()
  set(BC_KEYGEN bc_keygen)
endif()

if(BINARYCRYPT_KEY_FILE)
  get_filename_component(BC_KEY_FILE_ABS "${BINARYCRYPT_KEY_FILE}" ABSOLUTE)
  set(BC_KEY_DIR ${CMAKE_BINARY_DIR}/generated/fixed)
  add_custom_command(
    OUTPUT ${BC_KEY_DIR}/bc_key_data.h
    COMMAND ${CMAKE_COMMAND} -E make_directory ${BC_KEY_DIR}
    COMMAND ${BC_KEYGEN} --from-file ${BC_KEY_FILE_ABS} ${BC_KEY_DIR}/bc_key_data.h
    DEPENDS ${BC_KEY_FILE_ABS}
    COMMENT "Reading the BinaryCrypt key from BINARYCRYPT_KEY_FILE"
    VERBATIM
  )
else()
  set(BC_KEY_DIR ${CMAKE_BINARY_DIR}/generated/random)
  add_custom_command(
    OUTPUT ${BC_KEY_DIR}/bc_key_data.h
    COMMAND ${CMAKE_COMMAND} -E make_directory ${BC_KEY_DIR}
    COMMAND ${BC_KEYGEN} --random ${BC_KEY_DIR}/bc_key_data.h
    COMMENT "Generating a random BinaryCrypt key"
    VERBATIM
  )
endif()

# Only the tool and the launcher link this: they share the key of this build.
add_library(bc_build_key STATIC common/bc_key.c ${BC_KEY_DIR}/bc_key_data.h)
target_include_directories(bc_build_key PRIVATE ${BC_KEY_DIR})
target_link_libraries(bc_build_key PUBLIC bc_core)

# ---------------------------------------------------------------------------------------------
# Launcher: shipped with the game. No console window on Windows (errors use a message box).

add_executable(bc_launcher WIN32 launcher/bc_launcher.c launcher/bc_online.c)
target_link_libraries(bc_launcher PRIVATE bc_build_key)
target_compile_options(bc_launcher PRIVATE ${BC_WARNINGS})
if(WIN32)
  # crypt32: DPAPI for the online key cache. shell32: CommandLineToArgvW.
  target_link_libraries(bc_launcher PRIVATE crypt32 shell32)
endif()
if(MSVC)
  target_link_options(bc_launcher PRIVATE /ENTRY:mainCRTStartup)
endif()

# ---------------------------------------------------------------------------------------------
# Tool: GUI editor and headless batch. Never shipped with a game.

add_executable(bc_tool tool/bc_tool_main.c)
target_link_libraries(bc_tool PRIVATE bc_build_key)
target_compile_options(bc_tool PRIVATE ${BC_WARNINGS})

if(BINARYCRYPT_BUILD_GUI)
  # An installed raylib first (cmake/Findraylib.cmake also finds the prebuilt Windows package in
  # ../Libs/raylib-5.5_win64_msvc16), otherwise the pinned upstream release.
  find_package(raylib QUIET)
  if(TARGET raylib)
    set(BC_RAYLIB raylib)
  elseif(TARGET raylib::raylib)
    set(BC_RAYLIB raylib::raylib)
    if(WIN32)
      list(APPEND BC_RAYLIB opengl32 gdi32 winmm)
    endif()
  elseif(BINARYCRYPT_FETCH_RAYLIB)
    include(FetchContent)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_GAMES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(raylib
      GIT_REPOSITORY https://github.com/raysan5/raylib.git
      GIT_TAG 5.5
      GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(raylib)
    set(BC_RAYLIB raylib)
  else()
    message(FATAL_ERROR "raylib not found: install it, enable BINARYCRYPT_FETCH_RAYLIB or set BINARYCRYPT_BUILD_GUI=OFF")
  endif()

  # Vendored raygui, compiled apart with default warnings.
  add_library(raygui_impl STATIC tool/raygui_impl.c)
  target_include_directories(raygui_impl PUBLIC tool/third_party)
  target_link_libraries(raygui_impl PUBLIC ${BC_RAYLIB})

  # Editor font: Montserrat Medium, the typeface of upbge.org (SIL OFL 1.1, tool/fonts/OFL.txt),
  # embedded as data the way Blender embeds its UI fonts. Subset of github.com/JulietaUla/Montserrat
  # (commit 555facf) to the glyphs the editor rasterizes (bc_gui_load_font):
  #   pyftsubset Montserrat-Medium.ttf --unicodes="U+0020-007E,U+00A0-017F,U+2013,U+2014,U+2018,U+2019,U+201C,U+201D,U+2022,U+2026,U+20AC"
  #              --no-hinting --layout-features='' --name-IDs='*'
  set(BC_FONT_DIR ${CMAKE_BINARY_DIR}/generated/font)
  add_custom_command(
    OUTPUT ${BC_FONT_DIR}/bc_font_data.h
    COMMAND ${CMAKE_COMMAND} -DIN=${CMAKE_CURRENT_SOURCE_DIR}/tool/fonts/Montserrat-Medium.ttf
            -DOUT=${BC_FONT_DIR}/bc_font_data.h -DNAME=bc_font_montserrat
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/bc_bin2c.cmake
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tool/fonts/Montserrat-Medium.ttf ${CMAKE_CURRENT_SOURCE_DIR}/cmake/bc_bin2c.cmake
    COMMENT "Embedding the editor font"
    VERBATIM
  )

  target_sources(bc_tool PRIVATE tool/bc_dialog.c tool/bc_gui.c ${BC_FONT_DIR}/bc_font_data.h)
  target_include_directories(bc_tool PRIVATE ${BC_FONT_DIR})
  target_compile_definitions(bc_tool PRIVATE BC_WITH_GUI)
  target_link_libraries(bc_tool PRIVATE raygui_impl)
  if(WIN32)
    target_link_libraries(bc_tool PRIVATE comdlg32 shell32 ole32)
  endif()
endif()

# ---------------------------------------------------------------------------------------------
# Tests

include(CTest)
if(BUILD_TESTING)
  add_executable(bc_tests tests/bc_tests.c)
  target_link_libraries(bc_tests PRIVATE bc_build_key)
  if(WIN32)
    target_link_libraries(bc_tests PRIVATE version) # GetFileVersionInfo: checks the branding.
  endif()
  target_compile_options(bc_tests PRIVATE ${BC_WARNINGS})
  add_test(NAME bc_tests COMMAND bc_tests ${CMAKE_CURRENT_BINARY_DIR}/test_work/unit)
  add_test(NAME bc_tests_clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_BINARY_DIR}/test_work/unit)
  set_tests_properties(bc_tests_clean PROPERTIES FIXTURES_SETUP bc_unit_work)
  set_tests_properties(bc_tests PROPERTIES FIXTURES_REQUIRED bc_unit_work)

  # Stand-in for the UPBGE player: receives the key through the pipe contract and checks that the
  # main file decrypts to the expected bytes. It does not link the build key.
  add_executable(bc_fake_player tests/bc_fake_player.c)
  target_link_libraries(bc_fake_player PRIVATE bc_core)
  target_compile_options(bc_fake_player PRIVATE ${BC_WARNINGS})

  # Stand-in key provider and key server in one (online key games).
  add_executable(bc_fake_provider tests/bc_fake_provider.c)
  target_link_libraries(bc_fake_provider PRIVATE bc_core)
  target_compile_options(bc_fake_provider PRIVATE ${BC_WARNINGS})

  add_test(NAME bc_end_to_end
    COMMAND ${CMAKE_COMMAND}
      -DBC_TOOL=$<TARGET_FILE:bc_tool>
      -DBC_PLAYER=$<TARGET_FILE:bc_fake_player>
      -DBC_TESTS=$<TARGET_FILE:bc_tests>
      -DBC_PROVIDER=$<TARGET_FILE:bc_fake_provider>
      -DBC_EXE_SUFFIX=${CMAKE_EXECUTABLE_SUFFIX}
      "-DBC_RUNNER=${CMAKE_CROSSCOMPILING_EMULATOR}"
      -DBC_WORK=${CMAKE_CURRENT_BINARY_DIR}/test_work/end_to_end
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/end_to_end.cmake
  )

  # Reference key server and providers (keyserver/, MIT). With Python and its "cryptography"
  # package, the whole chain runs: launcher -> bc_provider_dev -> bc_keyserver.py -> player.
  find_package(CURL QUIET)
  if(WIN32 OR CURL_FOUND)
    add_subdirectory(keyserver/providers)
  endif()
  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_FOUND AND NOT CMAKE_CROSSCOMPILING)
    execute_process(COMMAND ${Python3_EXECUTABLE} -c "import cryptography"
                    RESULT_VARIABLE bc_missing_cryptography OUTPUT_QUIET ERROR_QUIET)
    if(bc_missing_cryptography EQUAL 0)
      # No __pycache__ in the source tree.
      set(bc_keyserver_env BC_TEST_WORK=${CMAKE_CURRENT_BINARY_DIR}/test_work PYTHONDONTWRITEBYTECODE=1)
      if(TARGET bc_provider_dev)
        list(APPEND bc_keyserver_env
          BC_TOOL=$<TARGET_FILE:bc_tool>
          BC_PLAYER=$<TARGET_FILE:bc_fake_player>
          BC_PROVIDER_DEV=$<TARGET_FILE:bc_provider_dev>)
      endif()
      add_test(NAME bc_keyserver
        COMMAND ${Python3_EXECUTABLE} -m unittest -v test_keyserver
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/keyserver/tests)
      set_tests_properties(bc_keyserver PROPERTIES ENVIRONMENT "${bc_keyserver_env}")
    endif()
  endif()
endif()
