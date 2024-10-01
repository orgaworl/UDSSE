# cmake
cmake_minimum_required (VERSION 3.2)
project (UDSSE)

# bin dir
set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# .h dir
#include_directories (include)
include_directories(${PCL_INCLUDE_DIRS} include)

# option
add_compile_options( -L. -lpbc -lgmp -lssl -lcrypto -w ) 
#set(CMAKE_CXX_FLAGS "-L. -lpbc -lgmp -lssl -lcrypto")


# source code
aux_source_directory(${PROJECT_SOURCE_DIR}/src SRC_LIST)

# set( TEST src/test/testRSA.cpp)
# add_executable (rsa.bin ${SRC_LIST} ${TEST})

set(TEST src/test/testServer.cpp)
add_executable (server.bin ${SRC_LIST} ${TEST})

set(TEST src/test/testClient.cpp)
add_executable (client.bin ${SRC_LIST} ${TEST})

set(TEST src/test/testUDSSE.cpp)
add_executable (benchMark.bin ${SRC_LIST} ${TEST})

# link libraries
# target_link_libraries(rsa.bin gmp ssl pbc crypto)
target_link_libraries(server.bin gmp ssl pbc crypto)
target_link_libraries(client.bin gmp ssl pbc crypto)
target_link_libraries(benchMark.bin gmp ssl pbc crypto)
