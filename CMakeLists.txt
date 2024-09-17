cmake_minimum_required(VERSION 3.6.3)
project(kvsice C)

include(iceFilePaths.cmake)

add_library(kvsice ${ICE_SOURCES})

target_include_directories(kvsice PUBLIC
                           ${ICE_INCLUDE_PUBLIC_DIRS})

# install header files
install(
    FILES ${ICE_INCLUDE_PUBLIC_FILES}
    DESTINATION include/kvsice)

# install ICE library
install(
    TARGETS kvsice
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")