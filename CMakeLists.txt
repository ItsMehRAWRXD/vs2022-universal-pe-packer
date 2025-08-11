cmake_minimum_required(VERSION 3.15)
project(StarMasterToolkit VERSION 2.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4 /O2)
    add_compile_definitions(_WIN32_WINNT=0x0601)
else()
    add_compile_options(-Wall -Wextra -O3)
endif()

# Platform-specific libraries
if(WIN32)
    set(PLATFORM_LIBS 
        wininet shlwapi shell32 ole32 oleaut32 urlmon taskschd 
        ws2_32 crypt32 advapi32 user32 kernel32)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CURL REQUIRED libcurl)
    set(PLATFORM_LIBS ${CURL_LIBRARIES} pthread)
endif()

# Main executable
add_executable(StarMasterToolkit StarMasterToolkit.cpp)

# Link libraries
target_link_libraries(StarMasterToolkit ${PLATFORM_LIBS})

# Include directories
if(NOT WIN32)
    target_include_directories(StarMasterToolkit PRIVATE ${CURL_INCLUDE_DIRS})
    target_compile_options(StarMasterToolkit PRIVATE ${CURL_CFLAGS_OTHER})
endif()

# Install targets
install(TARGETS StarMasterToolkit
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static)

# Documentation
install(FILES README.md DESTINATION share/doc/StarMasterToolkit)

# Create package
set(CPACK_PACKAGE_NAME "StarMasterToolkit")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Unified Security Tools Platform")
set(CPACK_PACKAGE_VENDOR "Star-2 Development Team")

include(CPack)