cmake_minimum_required(VERSION 3.15.6)
project(EasyTshark)

set(CMAKE_CXX_STANDARD 14)

# 设置字符集为 UTF-8
if(MSVC)
    add_compile_options("/utf-8")
endif()

add_executable(EasyTshark
        main.cpp
        utils/ProcessUtil.cpp
        utils/translator_util.hpp
        data/packet_sql.hpp
        data/tshark_datatype.h
        task/TsharkManager.cpp
        data/TsharkDataBase.hpp
        controller/packet_controller.hpp
        utils/ip2region_util.cpp
        third_library/ip2region/xdb_bench.cc
        third_library/ip2region/xdb_search.cc
        third_library/loguru/loguru.cpp
        third_library/sqlite3/sqlite3.c)

include_directories(third_library)

# 添加网络库链接
if (MINGW)
    target_link_libraries(EasyTshark ws2_32)
else ()
    target_link_libraries(EasyTshark)
endif ()