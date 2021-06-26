
add_executable(lowmc_test lowmc.cpp common/lowmccircuit.cpp common/LowMC.cpp)
target_link_libraries(lowmc_test ABY::aby ENCRYPTO_utils::encrypto_utils)

add_executable(lowmc_nonmpc lowmc_nonmpc.cpp common/LowMC.cpp)
target_link_libraries(lowmc_nonmpc ABY::aby ENCRYPTO_utils::encrypto_utils)
