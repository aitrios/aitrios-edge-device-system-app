set(TARGET ut_initial_setting_app_ps_stub)

## For Targe Excecutable(SCHEME_CHANGE_ENABLE OFF)
set(COMPILE_SRCS
    # Unit Test SourceCode
    ./ut_initial_setting_app_ps_stub.c
    ${MOCK_SRCS}

    # Test Target SourceCode
    ${REPOSITRY_TOP_DIR}/src/initial_setting_app/initial_setting_app_ps_stub.c
)

link_directories(
)

set(LIBS
    cmocka
)

set(WRAP_SYMBOLES
    ${WRAP_ESF_SYMBOLES}
    ${WRAP_PRINTF_SYMBOLES}
    ${WRAP_SYSLOG_SYMBOLES}
    ${WRAP_SLEEP_SYMBOLES}
    ${WRAP_ISA_BUTTON_SYMBOLES}
)

string(CONCAT WRAP_SYMBOLES "--wrap=" "${WRAP_SYMBOLES}")
string(REPLACE ";" ",--wrap=" WRAP_SYMBOLES "${WRAP_SYMBOLES}")
#message("${WRAP_SYMBOLES}")

add_executable(${TARGET}
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
    INITIAL_SETTING_APP_PS_STUB
    )
target_link_options(${TARGET}
    PUBLIC
    "-Wl,${WRAP_SYMBOLES}"
    )
