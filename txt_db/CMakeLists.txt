cmake_minimum_required(VERSION 3.10)

set(MODULE_NAME txt_db)

find_package(OpenSSL REQUIRED)

# 添加链接库
set(EXTRA_LIBS ${EXTRA_LIBS} "${OPENSSL_LIBRARIES}")


# 添加头文件路径
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ======================================================
# 自动包含当前目录代码文件
# aux_source_directory(. DIR_SRCS)
set(txt_db_example_file "txt_db_example.cc")

# 生成可执行文件
add_executable(txt_db_example ${txt_db_example_file})

# 添加可执行文件使用的链接库
target_link_libraries(txt_db_example ${EXTRA_LIBS})

# 指定安装的文件信息
install(TARGETS txt_db_example DESTINATION bin)
#install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/test.cnf" DESTINATION bin)