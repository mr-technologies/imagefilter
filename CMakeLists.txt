cmake_minimum_required(VERSION 3.10)
project(imagefilter LANGUAGES CXX)

set(IFF_SDK_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../.. CACHE PATH "IFF SDK package root directory (should contain `version.txt` file)")

get_cmake_property(build_type_ignored GENERATOR_IS_MULTI_CONFIG)
if(NOT CMAKE_BUILD_TYPE AND NOT build_type_ignored)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
    message(STATUS "Defaulting to ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE")
endif()

add_executable(${PROJECT_NAME}
        ${PROJECT_NAME}.cpp
        )

set_target_properties(${PROJECT_NAME} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH_USE_LINK_PATH TRUE
        )
if(APPLE)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            INSTALL_RPATH "@loader_path"
            )
elseif(UNIX)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            INSTALL_RPATH "$ORIGIN"
            )
endif()

file(GENERATE OUTPUT CopyConfig-$<CONFIG>.cmake CONTENT "
        if(NOT EXISTS \${DEST_DIR}/${PROJECT_NAME}.json)
            file(INSTALL
                    ${PROJECT_NAME}.json
                    DESTINATION \${DEST_DIR}
                    )
        endif()
        ")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM COMMAND ${CMAKE_COMMAND}
        -D "DEST_DIR=$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        -P ${CMAKE_CURRENT_BINARY_DIR}/CopyConfig-$<CONFIG>.cmake
        )

if(NOT TARGET IFF::iffsdk)
    if(EXISTS ${IFF_SDK_ROOT}/version.txt)
        file(STRINGS ${IFF_SDK_ROOT}/version.txt iff_sdk_version LIMIT_COUNT 1)
        message(STATUS "Found IFF ${iff_sdk_version}")
    else()
        message(FATAL_ERROR "IFF SDK package not found at `${IFF_SDK_ROOT}`!")
    endif()
    add_library(IFF::iffsdk INTERFACE IMPORTED)
    set_property(TARGET IFF::iffsdk PROPERTY INTERFACE_INCLUDE_DIRECTORIES
            ${IFF_SDK_ROOT}/sdk/include
            )
    if(WIN32)
        set_property(TARGET IFF::iffsdk PROPERTY INTERFACE_LINK_LIBRARIES
                ${IFF_SDK_ROOT}/sdk/lib/iffsdk${CMAKE_LINK_LIBRARY_SUFFIX}
                )
    else()
        set_property(TARGET IFF::iffsdk PROPERTY INTERFACE_LINK_LIBRARIES
                ${IFF_SDK_ROOT}/sdk/lib/${CMAKE_SHARED_LIBRARY_PREFIX}iffsdk${CMAKE_SHARED_LIBRARY_SUFFIX}
                )
    endif()
    file(GENERATE OUTPUT CopySDK-$<CONFIG>.cmake CONTENT "
            file(INSTALL
                    sdk/lib/
                    DESTINATION \${DEST_DIR}
                    $<$<PLATFORM_ID:Windows>:PATTERN \"*${CMAKE_LINK_LIBRARY_SUFFIX}\" EXCLUDE>
                    )
            ")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            WORKING_DIRECTORY ${IFF_SDK_ROOT}
            VERBATIM COMMAND ${CMAKE_COMMAND}
            -D "DEST_DIR=$<TARGET_FILE_DIR:${PROJECT_NAME}>"
            -P ${CMAKE_CURRENT_BINARY_DIR}/CopySDK-$<CONFIG>.cmake
            )
endif()

if(NOT TARGET nlohmann_json::nlohmann_json)
    add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
    set_property(TARGET nlohmann_json::nlohmann_json PROPERTY INTERFACE_INCLUDE_DIRECTORIES
            ${IFF_SDK_ROOT}/samples/common
            )
endif()

find_package(Threads REQUIRED)

target_link_libraries(${PROJECT_NAME} PRIVATE
        IFF::iffsdk
        nlohmann_json::nlohmann_json
        Threads::Threads
        )
