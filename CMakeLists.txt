cmake_minimum_required(VERSION 3.9)
project(constant_time_constant_weight_encoding C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-DCPU_WORD_BITS=64 -Wall -pedantic -march=native -O3 ")

set(SOURCE_LIB
        library/combinadics_library.c
        library/constant_weight_codec.c)

set(HEADER_LIB
        include/constant_weight_codec.h
        include/rng.h)

include_directories(include)

foreach(nval 71798 115798 178102 20326)
  add_executable(reproduce_paper_results_nvalue_${nval} reproduce_paper_results.c reproduce_paper_results.c ${SOURCE_LIB})
  target_link_libraries(reproduce_paper_results_nvalue_${nval} m)
  set_property(TARGET reproduce_paper_results_nvalue_${nval} APPEND PROPERTY COMPILE_FLAGS "-DPARAMETER_SET=${nval}")
endforeach()
