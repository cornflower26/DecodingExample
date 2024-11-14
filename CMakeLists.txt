cmake_minimum_required(VERSION 3.22)
project(DecodingExample)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lomp=libomp")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xclang -fopenmp -L/usr/local/Cellar/libomp/18.1.2/lib -I/usr/local/Cellar/libomp/18.1.2/include")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
set(CMAKE_CXX_STANDARD 17)

add_executable(DecodingExample main.cpp)

add_library(openfhecorelib SHARED IMPORTED)
add_library(openfhepkelib SHARED IMPORTED)

set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEpke.so")
set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEcore.so")

include_directories("/usr/local/include/openfhe")
include_directories("/usr/local/include/openfhe/core")
include_directories("/usr/local/include/openfhe/pke")
include_directories("/usr/local/include/openfhe/binfhe")

link_directories("/usr/local/lib")
link_directories("/usr/include")

#target_link_libraries(SLAP omp)
target_link_libraries(DecodingExample OPENFHEcore)
target_link_libraries(DecodingExample OPENFHEpke)
target_link_libraries(DecodingExample OPENFHEbinfhe)

set(CMAKE_PREFIX_PATH "/usr/local/lib/OpenFHE")
find_package("OpenFHE")
