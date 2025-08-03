find_path(RAYLIB_INCLUDE_DIR raylib.h
  HINTS
    $ENV{RAYLIB_INCLUDE_DIR}
    $ENV{RAYLIB_DIR}/include
    ${CMAKE_PREFIX_PATH}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../Libs/raylib-5.5_win64_msvc16/include
    ENV PATH
  PATH_SUFFIXES include
)

find_path (RAYLIB_LIB_DIR raylib.lib
  HINTS
    $ENV{RAYLIB_LIB_DIR}
    $ENV{RAYLIB_DIR}/lib
    ${CMAKE_PREFIX_PATH}/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../Libs/raylib-5.5_win64_msvc16/lib
    ENV PATH
  PATH_SUFFIXES lib
)

find_library(RAYLIB_LIBRARY NAMES raylib
  HINTS
    $ENV{RAYLIB_LIBRARY_DIR}
    $ENV{RAYLIB_DIR}/lib
    ${CMAKE_PREFIX_PATH}/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../Libs/raylib-5.5_win64_msvc16/lib
    ENV PATH
  PATH_SUFFIXES lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(raylib DEFAULT_MSG RAYLIB_LIBRARY RAYLIB_INCLUDE_DIR)

if(raylib_FOUND)
  add_library(raylib::raylib UNKNOWN IMPORTED)
  set_target_properties(raylib::raylib PROPERTIES
    IMPORTED_LOCATION "${RAYLIB_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${RAYLIB_INCLUDE_DIR}"
  )
endif()
