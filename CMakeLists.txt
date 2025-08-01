cmake_minimum_required(VERSION 3.10)
project(UPBGE_BinaryCrypt C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
find_package(raylib REQUIRED)

# -- Generate random password if not defined --
if(NOT DEFINED ENV{UPBGE_BINARYCRYPT_PASSWORD})
    execute_process(COMMAND openssl rand -hex 32
                    OUTPUT_VARIABLE GENERATED_PW
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(ENV{UPBGE_BINARYCRYPT_PASSWORD} "${GENERATED_PW}")
endif()

# -- Generate random salt if not defined --
if(NOT DEFINED ENV{UPBGE_BINARYCRYPT_SALT})
    execute_process(COMMAND openssl rand -hex 16
                    OUTPUT_VARIABLE GENERATED_SALT
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(ENV{UPBGE_BINARYCRYPT_SALT} ${GENERATED_SALT})
endif()

# -- Compilation definitions --
set(PASSWORD "$ENV{UPBGE_BINARYCRYPT_PASSWORD}")
set(SALT_HEX $ENV{UPBGE_BINARYCRYPT_SALT})

string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1, " SALT_BYTES "${SALT_HEX}")

#add_compile_definitions(ENCRYPTION_PASSWORD="${PASSWORD}")
#add_compile_definitions(ENCRYPTION_SALT=${SALT_BYTES})

add_compile_definitions(ENCRYPTION_PASSWORD="mi_contraseña_secreta")
add_compile_definitions(ENCRYPTION_SALT="0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F")

add_subdirectory(aes)

# Configuración para evitar conflictos de CRT
if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# --- upbge_binarycrypt_tool ---
set(RAYLIB_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../Libs/raylib-5.5_win64_msvc16/include/" CACHE PATH "Path to raylib include")
set(RAYLIB_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../Libs/raylib-5.5_win64_msvc16/lib/" CACHE PATH "Path to raylib lib")

add_executable(upbge_binarycrypt_tool
    upbge_binarycrypt_tool/main_tool.c
)

target_include_directories(upbge_binarycrypt_tool PRIVATE ${RAYLIB_INCLUDE_DIR})
target_link_directories(upbge_binarycrypt_tool PRIVATE ${RAYLIB_LIB_DIR})
target_link_libraries(upbge_binarycrypt_tool PRIVATE raylib tiny_aes winmm)

# --- upbge_binarycrypt_launcher ---
add_executable(upbge_binarycrypt_launcher
    upbge_binarycrypt_launcher/main_launcher.c
)
target_link_libraries(upbge_binarycrypt_launcher PRIVATE tiny_aes)
