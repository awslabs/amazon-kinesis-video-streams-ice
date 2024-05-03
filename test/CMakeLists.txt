cmake_minimum_required(VERSION 3.6.3)

project(IceTest VERSION 0.0.1 LANGUAGES C)

set(CMAKE_ROOT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting CMAKE_BUILD_TYPE to Release by default")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

include( ${CMAKE_CURRENT_LIST_DIR}/../source/dependency/amazon-kinesis-video-streams-stun/stunFilePaths.cmake )

file(
  GLOB
  ICE_SOURCE_FILES
  "${CMAKE_CURRENT_LIST_DIR}/../source/*.c" )

file(
  GLOB
  ICE_TEST_SOURCE_FILES
  "${CMAKE_CURRENT_LIST_DIR}/*.c" )

set( ICE_TEST_INCLUDE_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/" )

set( ICE_INCLUDE_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/../source/include" )

add_executable(
    IceTest
    ${ICE_SOURCE_FILES}
    ${ICE_TEST_SOURCE_FILES}
    ${STUN_SOURCES} )

target_include_directories( IceTest PRIVATE
                            ${ICE_TEST_INCLUDE_DIRS}
                            ${ICE_INCLUDE_DIRS}
                            ${STUN_INCLUDE_PUBLIC_DIRS} )
