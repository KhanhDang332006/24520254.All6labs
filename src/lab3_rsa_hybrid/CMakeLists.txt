# Khai báo file nguồn và file Header
set(LAB3_SOURCES rsatool.cpp)
set(LAB3_HEADERS json.hpp) # Khai báo để VS Code và CMake nhận diện

# Build thu vien dong (.dll hoac .so) de Python GUI su dung
add_library(lab3_dll SHARED ${LAB3_SOURCES} ${LAB3_HEADERS})
target_link_libraries(lab3_dll PRIVATE crypto_core)
target_compile_definitions(lab3_dll PRIVATE RSATOOL_BUILD_DLL)

# Build file thuc thi CLI de test rieng
add_executable(lab3_cli ${LAB3_SOURCES} ${LAB3_HEADERS})
target_link_libraries(lab3_cli PRIVATE crypto_core)