# Include filepaths for source and include.
include( ${MODULE_ROOT_DIR}/iceFilePaths.cmake )
include( ${MODULE_ROOT_DIR}/source/dependency/amazon-kinesis-video-streams-stun/stunFilePaths.cmake )

# ====================  Define your project name (edit) ========================
set( project_name "ice_api" )

message( STATUS "${project_name}" )

# =====================  Create your mock here  (edit)  ========================

# List the files to mock here.
list(APPEND mock_list
            "${MODULE_ROOT_DIR}/source/include/ice_data_types.h"
        )
# List the directories your mocks need.
list(APPEND mock_include_list
            ${ICE_INCLUDE_PUBLIC_DIRS}
            ${MODULE_ROOT_DIR}/test/unit-test
        )

# List the definitions of your mocks to control what to be included.
list(APPEND mock_define_list
            ""
       )

# ================= Create the library under test here (edit) ==================

# List the files you would like to test here.
list(APPEND real_source_files
            ${MODULE_ROOT_DIR}/source/ice_api_private.c
            ${MODULE_ROOT_DIR}/source/ice_api.c
            ${MODULE_ROOT_DIR}/source/transaction_id_store.c
            ${STUN_SOURCES}
        )
# List the directories the module under test includes.
list(APPEND real_include_directories
            ${ICE_INCLUDE_PUBLIC_DIRS}
            ${MODULE_ROOT_DIR}/test/unit-test
            ${CMOCK_DIR}/vendor/unity/src
            ${STUN_INCLUDE_PUBLIC_DIRS}
        )

# =====================  Create UnitTest Code here (edit)  =====================

# list the directories your test needs to include.
list(APPEND test_include_directories
            ${CMOCK_DIR}/vendor/unity/src
            ${ICE_INCLUDE_PUBLIC_DIRS}
            ${MODULE_ROOT_DIR}/test/unit-test
        )

# =============================  (end edit)  ===================================

set(mock_name "${project_name}_mock")
set(real_name "${project_name}_real")

create_mock_list(${mock_name}
                "${mock_list}"
                "${MODULE_ROOT_DIR}/test/unit-test/cmock/project.yml"
                "${mock_include_list}"
                "${mock_define_list}"
        )

create_real_library(${real_name}
                    "${real_source_files}"
                    "${real_include_directories}"
                    "${mock_name}"
        )

list(APPEND utest_link_list
            lib${real_name}.a
        )

list(APPEND utest_dep_list
            ${real_name}
        )

set(utest_name "${project_name}_utest")
set(utest_source "${project_name}/${project_name}_utest.c")

create_test(${utest_name}
            ${utest_source}
            "${utest_link_list}"
            "${utest_dep_list}"
            "${test_include_directories}"
        )
