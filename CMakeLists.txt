cmake_minimum_required(VERSION 3.15)
project(Crypto_Labs_All CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# 1. Cấu hình tìm Crypto++ linh hoạt cho cả Windows (truyền -DCRYPTOPP_ROOT) và Linux
find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/rsa.h
    HINTS ${CRYPTOPP_ROOT}/include $ENV{CRYPTOPP_ROOT}/include /usr/include
)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp cryptlib
    HINTS ${CRYPTOPP_ROOT}/lib ${CRYPTOPP_ROOT}/lib64 ${CRYPTOPP_ROOT}/lib/cryptopp/gcc $ENV{CRYPTOPP_ROOT}/lib /usr/lib
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(WARNING "Khong tim thay Crypto++. Truyen -DCRYPTOPP_ROOT de chi dinh duong dan.")
endif()

# Gom cac module core de xai chung
add_library(crypto_core INTERFACE)
target_include_directories(crypto_core INTERFACE ${CRYPTOPP_INCLUDE_DIR})
target_link_libraries(crypto_core INTERFACE ${CRYPTOPP_LIBRARY})

if(WIN32)
    target_link_libraries(crypto_core INTERFACE ws2_32 crypt32)
    target_compile_definitions(crypto_core INTERFACE _WIN32_WINNT=0x0602)
else()
    target_link_libraries(crypto_core INTERFACE pthread)
endif()

# 2. Add subdirectories cho cac Lab (comment nhung lab chua lam)
# add_subdirectory(src/lab1_sym)
# add_subdirectory(src/lab2_aes)
add_subdirectory(src/lab3_rsa_hybrid)
# add_subdirectory(src/lab4_hash)
# add_subdirectory(src/lab5_sig)
# add_subdirectory(src/lab6_pqc)