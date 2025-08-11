#!/bin/bash

# Star Master Toolkit Build Script
# Cross-platform build automation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="StarMasterToolkit"
BUILD_DIR="$SCRIPT_DIR/build"
INSTALL_DIR="$SCRIPT_DIR/dist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    STAR MASTER TOOLKIT BUILD                    ║"
    echo "║                    Enhanced RNG + Unified Tools                 ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_status "Checking build dependencies..."
    
    # Check for CMake
    if ! command -v cmake &> /dev/null; then
        print_error "CMake is required but not installed"
        echo "  - Ubuntu/Debian: sudo apt install cmake"
        echo "  - CentOS/RHEL: sudo yum install cmake"
        echo "  - macOS: brew install cmake"
        exit 1
    fi
    
    # Check for compiler
    if command -v g++ &> /dev/null; then
        COMPILER="g++"
        print_status "Found compiler: $(g++ --version | head -n1)"
    elif command -v clang++ &> /dev/null; then
        COMPILER="clang++"
        print_status "Found compiler: $(clang++ --version | head -n1)"
    else
        print_error "No C++ compiler found (g++ or clang++)"
        exit 1
    fi
    
    # Check platform-specific dependencies
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Check for libcurl
        if ! pkg-config --exists libcurl; then
            print_warning "libcurl development headers not found"
            echo "  Install with: sudo apt install libcurl4-openssl-dev"
            echo "  Or: sudo yum install libcurl-devel"
        fi
    fi
}

setup_build_environment() {
    print_status "Setting up build environment..."
    
    # Clean previous build
    if [[ -d "$BUILD_DIR" ]]; then
        print_status "Cleaning previous build..."
        rm -rf "$BUILD_DIR"
    fi
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    mkdir -p "$INSTALL_DIR"
}

configure_build() {
    print_status "Configuring build with CMake..."
    
    cd "$BUILD_DIR"
    
    local cmake_args=(
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_INSTALL_PREFIX=$INSTALL_DIR"
    )
    
    # Add platform-specific options
    if [[ "$1" == "windows" ]]; then
        cmake_args+=(
            "-DCMAKE_TOOLCHAIN_FILE=$SCRIPT_DIR/cmake/mingw-w64.cmake"
            "-DCMAKE_SYSTEM_NAME=Windows"
        )
        print_status "Configuring for Windows cross-compilation..."
    else
        print_status "Configuring for native build..."
    fi
    
    cmake "${cmake_args[@]}" "$SCRIPT_DIR"
}

build_project() {
    print_status "Building $PROJECT_NAME..."
    
    cd "$BUILD_DIR"
    
    # Build with all available cores
    local cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    cmake --build . --config Release --parallel "$cores"
}

install_project() {
    print_status "Installing to $INSTALL_DIR..."
    
    cd "$BUILD_DIR"
    cmake --install . --config Release
}

package_release() {
    print_status "Creating release package..."
    
    cd "$BUILD_DIR"
    cpack -G TGZ
    
    if [[ -f *.tar.gz ]]; then
        mv *.tar.gz "$INSTALL_DIR/"
        print_status "Package created in $INSTALL_DIR/"
    fi
}

run_tests() {
    print_status "Running tests..."
    
    cd "$BUILD_DIR"
    if [[ -f "${PROJECT_NAME}" || -f "${PROJECT_NAME}.exe" ]]; then
        print_status "Build successful!"
        
        # Basic functionality test
        local executable="${PROJECT_NAME}"
        if [[ "$OSTYPE" == "msys" ]] || [[ "$1" == "windows" ]]; then
            executable="${PROJECT_NAME}.exe"
        fi
        
        if [[ -x "$executable" ]]; then
            print_status "Testing RNG system..."
            # Could add automated tests here
            print_status "Manual testing required - run the executable"
        fi
    else
        print_error "Build failed - executable not found"
        exit 1
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --target <platform>    Target platform: native, windows"
    echo "  --clean               Clean build directory only"
    echo "  --install             Install after building"
    echo "  --package             Create release package"
    echo "  --test                Run tests after building"
    echo "  --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Native build"
    echo "  $0 --target windows   # Cross-compile for Windows"
    echo "  $0 --install --package --test  # Full build with install and packaging"
}

main() {
    print_banner
    
    local target_platform="native"
    local do_install=false
    local do_package=false
    local do_test=false
    local clean_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --target)
                target_platform="$2"
                shift 2
                ;;
            --clean)
                clean_only=true
                shift
                ;;
            --install)
                do_install=true
                shift
                ;;
            --package)
                do_package=true
                shift
                ;;
            --test)
                do_test=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Clean only mode
    if [[ "$clean_only" == true ]]; then
        print_status "Cleaning build directory..."
        rm -rf "$BUILD_DIR"
        print_status "Clean complete"
        exit 0
    fi
    
    # Validate target platform
    if [[ "$target_platform" != "native" && "$target_platform" != "windows" ]]; then
        print_error "Invalid target platform: $target_platform"
        print_error "Supported platforms: native, windows"
        exit 1
    fi
    
    # Check for Windows cross-compilation requirements
    if [[ "$target_platform" == "windows" ]]; then
        if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
            print_error "MinGW-w64 cross-compiler not found"
            echo "  Install with: sudo apt install mingw-w64"
            exit 1
        fi
    fi
    
    # Build process
    check_dependencies
    setup_build_environment
    configure_build "$target_platform"
    build_project
    
    if [[ "$do_install" == true ]]; then
        install_project
    fi
    
    if [[ "$do_package" == true ]]; then
        package_release
    fi
    
    if [[ "$do_test" == true ]]; then
        run_tests "$target_platform"
    fi
    
    print_status "Build complete!"
    
    # Show final information
    echo ""
    echo -e "${GREEN}Build Summary:${NC}"
    echo "  Target Platform: $target_platform"
    echo "  Build Directory: $BUILD_DIR"
    echo "  Install Directory: $INSTALL_DIR"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Test the executable: $BUILD_DIR/$PROJECT_NAME"
    echo "  2. Read documentation: README.md"
    echo "  3. Check examples in examples/ directory"
}

# Run main function with all arguments
main "$@"