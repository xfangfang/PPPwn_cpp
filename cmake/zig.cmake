if (ZIG_NIGHTLY)
    set(ZIG_VERSION ${ZIG_NIGHTLY})
    set(ZIG_DOWNLOAD "http://ziglang.org/builds")
else ()
    set(ZIG_VERSION "0.12.0")
    set(ZIG_DOWNLOAD "http://ziglang.org/download/${ZIG_VERSION}")
endif ()

set(ZIG_PATHS "${CMAKE_BINARY_DIR}/vendor/zig")
find_program(ZIG zig PATHS ${ZIG_PATHS})

set(ZIG_HOST_ARCH ${CMAKE_HOST_SYSTEM_PROCESSOR})
if(NOT ZIG_HOST_ARCH)
    execute_process(
            COMMAND uname -m
            OUTPUT_VARIABLE ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(ZIG_HOST_ARCH "${ARCH}")
endif()
if (NOT ZIG_HOST_ARCH)
    set(ZIG_HOST_ARCH "x86_64")
elseif(ZIG_HOST_ARCH STREQUAL "arm64")
    set(ZIG_HOST_ARCH "aarch64")
endif ()

if(NOT ZIG)
    if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin")
        set(ZIG_DOWNLOAD "${ZIG_DOWNLOAD}/zig-macos-${ZIG_HOST_ARCH}-${ZIG_VERSION}.tar.xz")
    elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
        set(ZIG_DOWNLOAD "${ZIG_DOWNLOAD}/zig-linux-${ZIG_HOST_ARCH}-${ZIG_VERSION}.tar.xz")
    elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
        set(ZIG_DOWNLOAD "${ZIG_DOWNLOAD}/zig-windows-${ZIG_HOST_ARCH}-${ZIG_VERSION}.zip")
    endif()
    cmake_minimum_required(VERSION 3.14)
    include(FetchContent)
    FetchContent_Populate(
        vendor_zig
        URL "${ZIG_DOWNLOAD}"
        SOURCE_DIR "${CMAKE_BINARY_DIR}/vendor/zig"
        SUBBUILD_DIR "${CMAKE_BINARY_DIR}/CMakeFiles/vendor_zig_cache"
        BINARY_DIR "${CMAKE_BINARY_DIR}/CMakeFiles/vendor_zig_cache"
    )
endif()

find_program(ZIG zig PATHS ${ZIG_PATHS} REQUIRED)

if (ZIG_TARGET MATCHES "(.+)-(.+)-(.+)")
    set(ZIG_TARGET_ARCH ${CMAKE_MATCH_1})
    set(ZIG_TARGET_OS ${CMAKE_MATCH_2})
    set(ZIG_TARGET_ABI ${CMAKE_MATCH_3})
    if(ZIG_TARGET_ARCH STREQUAL "native")
        set(ZIG_TARGET_ARCH "${ZIG_HOST_ARCH}")
    endif ()
    if(ZIG_TARGET_OS MATCHES "macos")
        set(ZIG_TARGET_OS "Darwin")
    elseif(ZIG_TARGET_OS MATCHES "windows")
        set(ZIG_TARGET_OS "Windows")
    elseif(ZIG_TARGET_OS MATCHES "linux")
        set(ZIG_TARGET_OS "Linux")
    elseif(ZIG_TARGET_OS STREQUAL "native")
        if (APPLE)
            set(ZIG_TARGET_OS "Darwin")
        elseif (WIN32)
            set(ZIG_TARGET_OS "Windows")
        endif()
    else ()
        message(FATAL_ERROR "Unknown OS: ${ZIG_TARGET_OS}")
    endif()
elseif (ZIG_TARGET STREQUAL "native")
else ()
    message(WARNING "Unknown ZIG_TARGET: ${ZIG_TARGET}")
endif ()

message(STATUS "ZIG_TARGET: ${ZIG_TARGET}")
message(STATUS "OS: ${ZIG_TARGET_OS}")
message(STATUS "ARCH: ${ZIG_TARGET_ARCH}")

if (ZIG_TARGET_OS STREQUAL "Darwin")
    cmake_minimum_required(VERSION 3.14)
    include(FetchContent)
    message(STATUS "CMAKE_OSX_SYSROOT: ${CMAKE_OSX_SYSROOT}")
    set(MACOS_SDK "${CMAKE_BINARY_DIR}/vendor/macos_sdk")
    FetchContent_Populate(
        vendor_macos_sdk
        URL "https://github.com/xfangfang/zig-build-macos-sdk/releases/download/borealis/macos_sdk.tar.gz"
        SOURCE_DIR "${MACOS_SDK}"
        SUBBUILD_DIR "${CMAKE_BINARY_DIR}/CMakeFiles/macos_sdk_cache"
        BINARY_DIR "${CMAKE_BINARY_DIR}/CMakeFiles/macos_sdk_cache"
    )
    set(ZIG_C_FLAGS1 "-Wno-availability" "-Wno-nullability-completeness" "-Wno-typedef-redefinition" "-Wno-deprecated-declarations")
    set(ZIG_CPP_FLAGS1 "-Wno-elaborated-enum-base;${ZIG_C_FLAGS1}")
    set(ZIG_C_FLAGS2 "-I${MACOS_SDK}/include" "-L${MACOS_SDK}/lib" "-F${MACOS_SDK}/Frameworks")
    set(ZIG_CPP_FLAGS2 "-I${MACOS_SDK}/include/c++/v1;${ZIG_C_FLAGS2}")
endif()

set(ZIG_TOOLS "${CMAKE_BINARY_DIR}/vendor/zig-tools")
set(ZIG_TOOLS_IN "${CMAKE_CURRENT_LIST_DIR}/zig-tools")
set(ZIG_AR "${ZIG_TOOLS}/zig-ar.sh")
set(ZIG_CC "${ZIG_TOOLS}/zig-cc.sh")
set(ZIG_CPP "${ZIG_TOOLS}/zig-cpp.sh")
set(ZIG_RANLIB "${ZIG_TOOLS}/zig-ranlib.sh")
set(ZIG_RC "${ZIG_TOOLS}/zig-rc.sh")
configure_file(${ZIG_TOOLS_IN}/zig-ar.sh.in ${ZIG_AR} @ONLY)
configure_file(${ZIG_TOOLS_IN}/zig-cc.sh.in ${ZIG_CC} @ONLY)
configure_file(${ZIG_TOOLS_IN}/zig-cpp.sh.in ${ZIG_CPP} @ONLY)
configure_file(${ZIG_TOOLS_IN}/zig-ranlib.sh.in ${ZIG_RANLIB} @ONLY)
configure_file(${ZIG_TOOLS_IN}/zig-rc.sh.in ${ZIG_RC} @ONLY)