# Tiny-AES (Standalone library)
cmake_minimum_required(VERSION 3.10)
project(tiny_aes LANGUAGES C)

# Build as static library
add_library(tiny_aes STATIC aes.c)
target_include_directories(tiny_aes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Optional: Enable AES-NI optimizations
target_compile_definitions(tiny_aes PRIVATE AESNI=1)  # If CPU supports it
