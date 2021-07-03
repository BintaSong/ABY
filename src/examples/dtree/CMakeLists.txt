# cmake_minimum_required(VERSION 3.10)
# project(Privacy_Preserving_Decision_Tree_2019)

# set(CMAKE_CXX_STANDARD 11)

find_library(gmp required)
include_directories(/usr/include/eigen3/ /usr/include/ /usr/local/include/ ../libOTe/ ../libOTe/cryptoTools ../libOTe/cryptoTools/thirdparty/linux/boost ../libOTe/cryptoTools/thirdparty/linux/miracl)
link_directories(/usr/local/lib/ ../libOTe/lib/ ../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib)
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "./bin")

set(COMMON_SRCS common/common_src/types.cc common/common_src/types.h common/common_src/config.cc common/common_src/config.h common/common_src/secret_sharing.cc common/common_src/secret_sharing.h common/common_src/utils.cc common/common_src/utils.h)
#set(FSS_SRCS fss/fss-common.h fss/fss-common.cpp fss/fss-client.h fss/fss-client.cpp fss/fss-server.h fss/fss-server.cpp fss/openssl-aes.h)
set(TEST_SRCS common/LowMC.h common/LowMC.cpp common/pAES.h common/pAES.cpp common/tree_encrypt.h common/tree_encrypt.cpp common/feature_encrypt.cpp common/feature_encrypt.h common/common.h common/common.cpp common/tree_feature.h common/tree_feature.cpp common/aes_circuit.h common/aes_circuit.cpp common/tree_read_from_file.h common/tree_read_from_file.cpp common/dtread.h common/dtread.cpp common/ftread.h common/ftread.cpp common/test_oblivious_read.h common/test_oblivious_read.cpp test.cpp)

#add_executable(test ${COMMON_SRCS} ${FSS_SRCS} ${TEST_SRCS})
add_executable(test ${COMMON_SRCS} ${TEST_SRCS})

target_link_libraries(test boost_system pthread gmp gmpxx crypto ABY::aby ENCRYPTO_utils::encrypto_utils)
