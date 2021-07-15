
add_executable(elementary_test elementary_test.cpp common/elementary.cpp)
target_link_libraries(elementary_test ABY::aby ENCRYPTO_utils::encrypto_utils)
