cmake_minimum_required(VERSION 3.15)
project(CryptoLabs VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_POSITION_INDEPENDENT_CODE ON) # Cần để build .so trên Linux

# ==============================================================
# QUY HOẠCH LẠI THƯ MỤC OUTPUT CHO GỌN GÀNG
# ==============================================================
# Đưa các file thực thi (.exe) và thư viện động (.dll trên Win) vào thư mục bin/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Đưa các file thư viện tĩnh/import (.lib, .dll.a) vào thư mục lib/
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Đưa các file thư viện động (.so trên Linux) vào thư mục lib/
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
# ==============================================================

# 1. TỰ ĐỘNG TÌM THƯ VIỆN TRONG HỆ THỐNG
# (Sẽ tự tìm OpenSSL và Crypto++ bất kể người dùng cài ở ổ C: hay D: hay /usr/lib)
find_package(OpenSSL REQUIRED)
find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/cryptlib.h PATH_SUFFIXES include)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp cryptlib PATH_SUFFIXES lib lib64)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Lỗi: Không tìm thấy Crypto++. Vui lòng cài đặt qua MSYS2 (pacman) trên Windows hoặc apt trên Ubuntu.")
endif()

# 2. PHÂN NHÁNH THƯ VIỆN THEO HỆ ĐIỀU HÀNH
if(WIN32)
    # Đã thêm bcrypt vào đây để fix lỗi BCryptGenRandom
    set(OS_LIBS ws2_32 crypt32 bcrypt)
else()
    find_package(Threads REQUIRED)
    set(OS_LIBS Threads::Threads)
endif()

# ==============================================================
# 3. TỰ ĐỘNG QUÉT TOÀN BỘ FILE VÀ BUILD (KHÔNG CẦN CẬP NHẬT TÊN FILE)
# ==============================================================
# Lệnh này sẽ tự động tìm tất cả các file .cpp nằm trong thư mục src/ và các thư mục con
file(GLOB_RECURSE ALL_SRC_FILES "src/*.cpp")

foreach(SRC_FILE IN LISTS ALL_SRC_FILES)
    # Lấy tên file để làm tên tool (VD: rsatool.cpp -> rsatool)
    get_filename_component(TOOL_NAME ${SRC_FILE} NAME_WE)
    
    # Sinh ra cờ macro viết hoa (VD: RSATOOL_BUILD_DLL)
    string(TOUPPER "${TOOL_NAME}" TOOL_NAME_UPPER)
    set(DLL_MACRO "${TOOL_NAME_UPPER}_BUILD_DLL")

    # --- A. Tạo file thực thi (.exe / binary) ---
    add_executable(${TOOL_NAME} ${SRC_FILE})
    target_include_directories(${TOOL_NAME} PRIVATE ${CRYPTOPP_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${TOOL_NAME} PRIVATE ${CRYPTOPP_LIBRARY} OpenSSL::Crypto ${OS_LIBS})

    # --- B. Tạo file thư viện động (.dll / .so) ---
    add_library(${TOOL_NAME}_shared SHARED ${SRC_FILE})
    set_target_properties(${TOOL_NAME}_shared PROPERTIES 
        OUTPUT_NAME ${TOOL_NAME}
        IMPORT_SUFFIX ".a"                                
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib  
    )
    target_compile_definitions(${TOOL_NAME}_shared PRIVATE ${DLL_MACRO})
    target_include_directories(${TOOL_NAME}_shared PRIVATE ${CRYPTOPP_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${TOOL_NAME}_shared PRIVATE ${CRYPTOPP_LIBRARY} OpenSSL::Crypto ${OS_LIBS})
endforeach()