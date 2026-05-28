# src/lab1_sym_with_cryptopp/CMakeLists.txt

# Build thu vien dong (.dll hoac .so) de Python GUI su dung
add_library(lab1_dll SHARED aestool.cpp)
target_link_libraries(lab1_dll PRIVATE crypto_core)
target_compile_definitions(lab1_dll PRIVATE AESTOOL_BUILD_DLL)

# Build file thuc thi CLI de test
add_executable(aestool aestool.cpp)
target_link_libraries(aestool PRIVATE crypto_core)