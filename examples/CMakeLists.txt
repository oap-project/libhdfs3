include_directories(${libhdfs3_ROOT_SOURCES_DIR})

add_executable(dt dt.cpp)
target_link_libraries(dt libhdfs3-static)