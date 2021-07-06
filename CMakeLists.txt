cmake_minimum_required(VERSION 2.8.12)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "Crypto: Found ccache package... Activating...")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

set(LIB_MAJOR_VERSION "7")
set(LIB_MINOR_VERSION "0")
set(LIB_PATCH_VERSION "0")
set(LIB_VERSION_STRING "${LIB_MAJOR_VERSION}.${LIB_MINOR_VERSION}.${LIB_PATCH_VERSION}")

if(CMAKE_VERSION VERSION_LESS 3.0)
    project(crypto CXX)
    enable_language(CXX)
else()
    cmake_policy(SET CMP0048 NEW)
    project(crypto VERSION "${LIB_VERSION_STRING}" LANGUAGES CXX)
endif()

option(BUILD_TEST "Build test binary" OFF)
if(DEFINED ENV{BUILD_TEST})
    set(BUILD_TEST $ENV{BUILD_TEST})
endif()
if (BUILD_TEST)
    message(STATUS "Test binary added to targets list")
endif()

option(BUILD_SHARED "Build shared library in addition to static" OFF)
if(DEFINED ENV{BUILD_SHARED})
    set(BUILD_SHARED $ENV{BUILD_SHARED})
endif()
if(BUILD_SHARED)
    message(STATUS "Shared library added to targets list")
endif()

option(BUILD_NODEJS "Build Node.js Native C++ Addon Module" OFF)
if(DEFINED ENV{BUILD_NODEJS})
    set(BUILD_NODEJS $ENV{BUILD_NODEJS})
endif()
if (BUILD_NODEJS)
    message(STATUS "Activating Node.js Native C++ Addon Module")
endif()

option(BUILD_JS "Build Javascript & WASM Modules" OFF)
if(DEFINED ENV{BUILD_JS})
    set(BUILD_JS $ENV{BUILD_JS})
endif()
if(BUILD_JS)
    message(STATUS "Activating Javascript & WASM Modules")
endif()

option(BUILD_JS_DEBUG "Activate Javascript & WASM Debug Mode" OFF)
if(DEFINED ENV{BUILD_JS_DEBUG)
    set(BUILD_JS_DEBUG $ENV{BUILD_JS_DEBUG})
endif()
if(BUILD_JS_DEBUG)
    message(STATUS "Activating Javascript & WASM Debug Mode")
endif()

option(DEBUG_PRINT "Enable debug print statements" OFF)
if (DEFINED ENV{DEBUG_PRINT})
    set(DEBUG_PRINT $ENV{DEBUG_PRINT})
endif()
if(DEBUG_PRINT)
    add_compile_definitions(DEBUG_PRINT=1)
    message(STATUS "Activating debug print statements")
endif()

if(BUILD_NODEJS AND BUILD_JS)
    message(FATAL_ERROR "Cannot use both BUILD_NODEJS and BUILD_JS at the same time")
endif()

if(BUILD_NODEJS OR BUILD_JS)
    set(ARCH default CACHE STRING "CPU to build for: -march value or native")
endif()

## This section describes our general CMake setup options
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_INSTALL_RULES OFF FORCE)
set(CMAKE_SKIP_PACKAGE_ALL_DEPENDENCY ON FORCE)
set(CMAKE_SUPPRESS_REGENERATION ON)
set(CMAKE_POLICY_WARNING_CMP0048 OFF)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Enable c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

## We only build static binaries -- this is left here for our dependencies
set(STATIC ON CACHE BOOL FORCE "Link libraries statically? Forced to ON")
add_definitions(-DSTATICLIB)
add_definitions(-DRAPIDJSON_HAS_STDSTRING)

if(MSVC)
    add_definitions("/EHsc -std:c++17 /O2 /wd4267 /wd4996")
endif()

if(NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -O3")
endif()

add_subdirectory(external)

set(INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/rapidjson/include/rapidjson
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

include_directories(${INCLUDE_DIRECTORIES})

set(SOURCES
    src/audit.cpp
    src/base58.cpp
    src/bulletproofs.cpp
    src/bulletproofsplus.cpp
    src/cn_base58.cpp
    src/crypto_common.cpp
    src/hashing.cpp
    src/memory_helper.cpp
    src/mnemonics.cpp
    src/multisig.cpp
    src/random.cpp
    src/ringct.cpp
    src/ring_signature_borromean.cpp
    src/ring_signature_clsag.cpp
    src/ring_signature_triptych.cpp
    src/signature.cpp
    src/string_tools.cpp
)

add_library(crypto-static STATIC ${SOURCES})
target_link_libraries(crypto-static argon2 ed25519 cryptopp-static uint256t)
target_include_directories(crypto-static PUBLIC ${INCLUDE_DIRECTORIES})

if(WIN32)
    target_link_libraries(crypto-static ws2_32 advapi32 crypt32 gdi32 user32)
endif()

if(BUILD_SHARED)
    add_library(crypto-shared STATIC ${SOURCES})
    target_link_libraries(crypto-shared argon2 ed25519 cryptopp-static uint256t)
    target_include_directories(crypto-shared PUBLIC ${INCLUDE_DIRECTORIES})

    if(WIN32)
        target_link_libraries(crypto-shared ws2_32 advapi32 crypt32 gdi32 user32)
    endif()
endif()

if(NOT BUILD_NODEJS AND NOT BUILD_JS AND BUILD_TEST)
    set(TEST_SOURCES
        src/cryptotest.cpp
    )

    add_executable(cryptotest ${TEST_SOURCES})
    target_link_libraries(cryptotest crypto-static)
    set_property(TARGET cryptotest PROPERTY OUTPUT_NAME "cryptotest")
endif()

if(BUILD_NODEJS AND NOT BUILD_JS)
    set(ADDITIONAL_SOURCES
        src/nodejs_module.cpp
    )

    if(MSVC)
        # https://github.com/refack/node/blob/965ffc4cb9a55d26192a95485b57afe4573990b0/common.gypi#L275
        add_definitions("/wd4351 /wd4355 /wd4800 /wd4251 /wd4275 /wd4244 /wd4996")
    endif()

    add_library(crypto SHARED ${ADDITIONAL_SOURCES} ${CMAKE_JS_SRC})
    set_target_properties(crypto PROPERTIES PREFIX "" SUFFIX ".node")
    target_include_directories(crypto PRIVATE ${CMAKE_JS_INC})
    target_link_libraries(crypto crypto-static ${CMAKE_JS_LIB})
endif()

if(BUILD_JS)
    set(JS_SOURCES src/javascript_module.cpp)

    set(CMAKE_C_FLAGS "-O3 -flto -Wno-unused-variable -Wno-unused-value")
    set(CMAKE_CXX_FLAGS "-O3 -std=c++17 -flto -Wno-unused-variable -Wno-unused-value")

    set(JS_LINKFLAGS
        --llvm-opts 3
        -flto
        --closure 1
        -s SINGLE_FILE=1
        -s EXPORT_NAME="'Crypto'"
        -s MODULARIZE=1
        -s FILESYSTEM=0
        --no-entry
        --bind
    )

    string(REPLACE ";" " " JS_LINKFLAGS_STR "${JS_LINKFLAGS}")

    if(BUILD_JS_DEBUG)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s DISABLE_EXCEPTION_CATCHING=0")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s DISABLE_EXCEPTION_CATCHING=0")
        set(JS_LINKFLAGS_STR "${JS_LINKFLAGS_STR} -s DISABLE_EXCEPTION_CATCHING=0 -s ASSERTIONS=2")
    endif()

    add_executable(crypto-js ${JS_SOURCES})
    target_link_libraries(crypto-js crypto-static)
    set(JS_LINKER "${JS_LINKFLAGS_STR} -s WASM=0")
    message(STATUS "JS emcc flags: ${JS_LINKER}")
    set_target_properties(crypto-js PROPERTIES LINK_FLAGS "${JS_LINKER}" PREFIX "" SUFFIX ".js")

    add_executable(crypto-wasm ${JS_SOURCES})
    target_link_libraries(crypto-wasm crypto-static)
    set(WASM_LINKER "${JS_LINKFLAGS_STR} -s WASM=1 -s BINARYEN_METHOD='native-wasm'")
    message(STATUS "WASM emcc flags: ${WASM_LINKER}")
    set_target_properties(crypto-wasm PROPERTIES LINK_FLAGS "${WASM_LINKER}" PREFIX "" SUFFIX ".js")
endif()

foreach(flag_var
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    string(REGEX REPLACE "/RTC[^ ]*" "" ${flag_var} "${${flag_var}}")
    string(REGEX REPLACE "/Od" "" ${flag_var} "${${flag_var}}")
endforeach(flag_var)
