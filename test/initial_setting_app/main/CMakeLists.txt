set(TARGET ut_main)

## For Target Executable(SCHEME_CHANGE_ENABLE OFF)
set(COMPILE_SRCS
    # Unit Test SourceCode
    ./ut_main.c
    ${MOCK_SRCS}

    # Test Target SourceCode
    ${REPOSITRY_TOP_DIR}/src/initial_setting_app/main.c
)

if(DEFINED CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION)
    list(APPEND COMPILE_SRCS ${REPOSITRY_TOP_DIR}/src/private/qr_quality_optimization.c)
endif()

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
    ${WRAP_SENSCORD_SYMBOLES}
    ${WRAP_ESF_SENSOR_SYMBOLES}
    ${WRAP_ISA_PS_SYMBOLES}
    ${WRAP_ISA_DECODE_SYMBOLES}
    ${WRAP_ISA_DECODE_INTERNAL_SYMBOLES}
    ${WRAP_ISA_QRCODE_SYMBOLES}
    ${WRAP_ISA_BUTTON_SYMBOLES}
    ${WRAP_ISA_TIMER_SYMBOLES}
)

if(DEFINED CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION)
    list(APPEND WRAP_SYMBOLES ${WRAP_PRIVATE_QR_QUALITY_OPT_SYMBOLES})
endif()

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
    )
target_link_options(${TARGET}
    PUBLIC
    "-Wl,${WRAP_SYMBOLES}"
    )
