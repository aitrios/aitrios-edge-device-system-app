cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME retrofit_unit_test)
project(${PROJECT_NAME} LANGUAGES CXX C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# COMMON SETTING
option(RETROFIT_UNIT_DEBUG "unit test debug option" ON)
if(RETROFIT_UNIT_DEBUG)
    set(CFGOPT "-O0 -g -coverage")
    #set(CFGOPT "-O0 -g -fsanitize=address -fno-omit-frame-pointer")
else()
    set(CFGOPT "-O2")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ${CFGOPT}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -MMD -MP ${CFGOPT}")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fsanitize=address -fno-omit-frame-pointer ${CFGOPT}")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -MMD -MP -fsanitize=address -fno-omit-frame-pointer ${CFGOPT}")

set(TOPDIR ${CMAKE_SOURCE_DIR}/..)
#set(GTESTDIR ${TOPDIR}/../../gtest)
set(GTESTDIR /usr/local)

include_directories(
    ${TOPDIR}/test/include/
    ${TOPDIR}/../
    )

set(GTEST_LIBS
    ${GTESTDIR}/lib/libgtest.a
    ${GTESTDIR}/lib/libgtest_main.a
    ${GTESTDIR}/lib/libgmock.a
    ${GTESTDIR}/lib/libgmock_main.a
    )

link_libraries(${GTEST_LIBS})
link_libraries(pthread)
include_directories(${GTESTDIR}/include)

# ------------------------------
# unit tests (subdirectory)
# ------------------------------

#get_cmake_property(_variableNames VARIABLES)
#foreach (_variableName ${_variableNames})
#    message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()

add_subdirectory(src)

