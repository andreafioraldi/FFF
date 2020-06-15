cmake_minimum_required(VERSION 3.5)
project(FFF VERSION 1.0.0 LANGUAGES CXX)

set(DEFAULT_BUILD_TYPE "Release")

#set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pg -g -fno-omit-frame-pointer -fsanitize=address")
#set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -pg -g -fno-omit-frame-pointer -fsanitize=address")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

include(GNUInstallDirs)

file(GLOB SOURCE_FILES src/*.cc src/Executor/*.cc src/Input/*.cc src/Mutator/*.cc src/Queue/*.cc src/Stage/*.cc src/OS/*.cc src/OS/*/*.cc)

add_library(${PROJECT_NAME}_objects OBJECT ${SOURCE_FILES})

target_compile_features(${PROJECT_NAME}_objects PRIVATE cxx_std_17)
set_property(TARGET ${PROJECT_NAME}_objects PROPERTY POSITION_INDEPENDENT_CODE 1)

target_include_directories(${PROJECT_NAME}_objects PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE src)

add_library(${PROJECT_NAME} SHARED $<TARGET_OBJECTS:${PROJECT_NAME}_objects>)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1)

add_library(${PROJECT_NAME}_static STATIC $<TARGET_OBJECTS:${PROJECT_NAME}_objects>)

