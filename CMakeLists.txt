cmake_minimum_required(VERSION 3.28)

project(OOSRegionFaker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(DOBBY_DEBUG OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(Plugin.SymbolResolver OFF CACHE BOOL "" FORCE)
set(DEX_BUILDER_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(LSPLANT_BUILD_SHARED OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/Dobby)
add_subdirectory(third_party/LSPlant/lsplant/src/main/jni)

add_library(oos_region_faker SHARED
    native/oos_region_faker.cpp
)

target_include_directories(oos_region_faker PRIVATE
    native
    third_party/Dobby/include
    third_party/LSPlant/lsplant/src/main/jni/include
)
target_compile_features(oos_region_faker PRIVATE cxx_std_23)
target_compile_options(oos_region_faker PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -fvisibility=hidden
)
target_link_libraries(oos_region_faker PRIVATE
    log
    dl
    z
    dobby_static
    lsplant_static
)
