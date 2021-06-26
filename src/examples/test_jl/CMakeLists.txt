add_executable(add_test add_test.cpp common/add.cpp)
target_link_libraries(add_test ABY::aby ENCRYPTO_utils::encrypto_utils)
