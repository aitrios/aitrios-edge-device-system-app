set(TARGET ut_system_app_state)

## For Targe Excecutable(SCHEME_CHANGE_ENABLE OFF)
set(COMPILE_SRCS
    # Unit Test SourceCode
    ./ut_system_app_state.c
    ${MOCK_SRCS}

    # Test Target SourceCode
    ${REPOSITRY_TOP_DIR}/src/system_app/modules/SystemApp/system_app_state.c
)

link_directories(
)

set(LIBS
    cmocka
)

set(WRAP_SYMBOLES
    ${WRAP_ESF_SYMBOLES}
    ${WRAP_ESF_SENSOR_SYMBOLES}
    ${WRAP_EVP_SYMBOLES}
    ${WRAP_SENSCORD_SYMBOLES}
    ${WRAP_PRINTF_SYMBOLES}
    ${WRAP_SYSLOG_SYMBOLES}
    ${WRAP_SYSTEMAPP_CMN_SYMBOLES}
    ${WRAP_SYSTEMAPP_DEPLOY_SYMBOLES}
    ${WRAP_SYSTEMAPP_LED_SYMBOLES}
    ${WRAP_SYSTEMAPP_LOG_SYMBOLES}
    ${WRAP_SYSTEMAPP_TIMER_SYMBOLES}
    ${WRAP_STD_PTHREAD_H_SYMBOLES}
    ${WRAP_STD_TIME_H_SYMBOLES}
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
    SYSTEM_APP_STATE_STUB
    )
target_link_options(${TARGET}
    PUBLIC
    "-Wl,${WRAP_SYMBOLES}"
    )
