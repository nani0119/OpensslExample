cmake_minimum_required(VERSION 3.10)

set(MODULE_NAME ssl)

find_package(OpenSSL REQUIRED)

# 添加链接库
set(EXTRA_LIBS ${EXTRA_LIBS} "${OPENSSL_LIBRARIES}")


# 添加头文件路径
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ======================================================
# 自动包含当前目录代码文件
# aux_source_directory(. DIR_SRCS)
foreach(var ssl_client ssl_server ssl_http)
    # 生成可执行文件
    add_executable(${var}_example "${var}_example.cc")
    # 添加可执行文件使用的链接库
    target_link_libraries(${var}_example ${EXTRA_LIBS})
    # 指定安装的文件信息
    install(TARGETS ${var}_example DESTINATION bin)
    #install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/test.cnf" DESTINATION bin)
endforeach(var ssl_client ssl_server)