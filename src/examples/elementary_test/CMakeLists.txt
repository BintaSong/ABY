
add_executable(elementary_int elementary_test.cpp common/elementary_int.cpp)
target_link_libraries(elementary_int ABY::aby ENCRYPTO_utils::encrypto_utils)

add_executable(elementary_float common/elementary_float.cpp)
target_link_libraries(elementary_float ABY::aby ENCRYPTO_utils::encrypto_utils)
