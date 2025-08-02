cmake_minimum_required(VERSION 3.10)
project(UPBGE_BinaryCrypt C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
find_package(raylib REQUIRED)

# -- Generate random password --
execute_process(COMMAND openssl rand -hex 32
                OUTPUT_VARIABLE GENERATED_PW
                OUTPUT_STRIP_TRAILING_WHITESPACE)

# -- Generate random salt --
execute_process(COMMAND openssl rand -hex 16
                OUTPUT_VARIABLE GENERATED_SALT
                OUTPUT_STRIP_TRAILING_WHITESPACE)

# -- Show values --
message(STATUS "Generated Password: ${GENERATED_PW}")
message(STATUS "Generated Salt HEX: ${GENERATED_SALT}")

# -- Convert salt hex string to comma-separated bytes --
string(REGEX REPLACE "([0-9a-fA-F][0-9a-fA-F])" "0x\\1, " SALT_BYTES "${GENERATED_SALT}")
string(REGEX REPLACE ", $" "" SALT_BYTES "${SALT_BYTES}")  # remove trailing comma

add_compile_definitions(ENCRYPTION_PASSWORD="${GENERATED_PW}")
add_compile_definitions(ENCRYPTION_SALT=${SALT_BYTES})

#add_compile_definitions(ENCRYPTION_PASSWORD="mi_contraseña_secreta")
#add_compile_definitions(ENCRYPTION_SALT="0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F")

message(STATUS "Salt bytes: ${SALT_BYTES}")
message(STATUS "ENCRYPTION_PASSWORD: ${ENCRYPTION_PASSWORD}")
message(STATUS "ENCRYPTION_SALT: ${ENCRYPTION_SALT}")

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
