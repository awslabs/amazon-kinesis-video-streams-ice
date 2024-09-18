# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

# Ice library source files.
set( ICE_SOURCES
     "${CMAKE_CURRENT_LIST_DIR}/source/ice_api.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/ice_api_private.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/transaction_id_store.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/dependency/amazon-kinesis-video-streams-stun/source/stun_deserializer.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/dependency/amazon-kinesis-video-streams-stun/source/stun_serializer.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/dependency/amazon-kinesis-video-streams-stun/source/stun_endianness.c" )

# Ice library Public Include directories.
set( ICE_INCLUDE_PUBLIC_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/source/include"
     "${CMAKE_CURRENT_LIST_DIR}/source/dependency/amazon-kinesis-video-streams-stun/source/include" )
