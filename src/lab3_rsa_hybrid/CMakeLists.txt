# Build thu vien dong (.dll hoac .so) de Python GUI su dung
add_library(lab3_dll SHARED rsatool.cpp)
target_link_libraries(lab3_dll PRIVATE crypto_core)
# Define macro de export API tren Windows (khop voi code C++ cua ban)
target_compile_definitions(lab3_dll PRIVATE RSATOOL_BUILD_DLL)

# (Tuy chon) Build file thuc thi CLI de test rieng
add_executable(lab3_cli rsatool.cpp)
target_link_libraries(lab3_cli PRIVATE crypto_core)