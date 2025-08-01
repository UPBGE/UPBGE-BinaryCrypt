cmake_minimum_required(VERSION 3.10)
project(UPBGE_BinaryCrypt C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
find_package(raylib REQUIRED)

# -- Generate random password if not defined --
if(NOT DEFINED ENV{UPBGE_BINARYCRYPT_PASSWORD})
    execute_process(COMMAND openssl rand -hex 32
                    OUTPUT_VARIABLE GENERATED_PW
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(ENV{UPBGE_BINARYCRYPT_PASSWORD} ${GENERATED_PW})
endif()

# -- Generate random salt if not defined --
if(NOT DEFINED ENV{UPBGE_BINARYCRYPT_SALT})
    execute_process(COMMAND openssl rand -hex 16
                    OUTPUT_VARIABLE GENERATED_SALT
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(ENV{UPBGE_BINARYCRYPT_SALT} ${GENERATED_SALT})
endif()

# -- Compilation definitions --
set(PASSWORD $ENV{UPBGE_BINARYCRYPT_PASSWORD})
set(SALT_HEX $ENV{UPBGE_BINARYCRYPT_SALT})

string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1, " SALT_BYTES "${SALT_HEX}")

add_compile_definitions(ENCRYPTION_PASSWORD="${PASSWORD}")
add_compile_definitions(ENCRYPTION_SALT=${SALT_BYTES})

include_directories(aes)

# --- upbge_binarycrypt_tool ---
set(RAYLIB_INCLUDE_DIR "../Libs/raylib-5.5_win64_msvc16/include" CACHE PATH "Path to raylib include")
set(RAYLIB_LIB_DIR "../Libs/raylib-5.5_win64_msvc16/lib" CACHE PATH "Path to raylib lib")

add_executable(upbge_binarycrypt_tool
    upbge_binarycrypt_tool/main_tool.c
)

target_include_directories(upbge_binarycrypt_tool PRIVATE ${RAYLIB_INCLUDE_DIR})
target_link_libraries(upbge_binarycrypt_tool PRIVATE "${RAYLIB_LIB_DIR}/raylib.lib" PUBLIC tiny_aes)

# --- upbge_binarycrypt_launcher ---
add_executable(upbge_binarycrypt_launcher
    upbge_binarycrypt_launcher/main_launcher.c
)
target_link_libraries(upbge_binarycrypt_launcher PUBLIC tiny_aes)
