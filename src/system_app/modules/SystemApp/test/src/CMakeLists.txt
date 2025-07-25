set(TARGET unit_test)

## For Targe Excecutable(SCHEME_CHANGE_ENABLE OFF)
set(UT_SRCS
    ${TOPDIR}/test/src/ut_system_app_main.cpp
    ${TOPDIR}/test/src/ut_int_fix.cpp
)
set(COMPILE_SRCS
)
link_directories(
)

set(LIBS
)
set(INCS
    ${TOPDIR}
    ${TOPDIR}/test/src/
    ${TOPDIR}/test/include/
    ${TOPDIR}/../../include/
)
find_package(GTest)

add_executable(${TARGET}
    ${UT_SRCS}
    ${COMPILE_SRCS}
    )

target_link_libraries(${TARGET}
    PUBLIC
    ${LIBS}
    )

target_include_directories(${TARGET}
    PUBLIC
    ${INCS}
    )

target_compile_definitions(${TARGET}
    PUBLIC
    )

