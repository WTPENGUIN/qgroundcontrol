target_sources(${CMAKE_PROJECT_NAME}
    PRIVATE
        LinkConfiguration.cc
        LinkConfiguration.h
        LinkInterface.cc
        LinkInterface.h
        LinkManager.cc
        LinkManager.h
        LogReplayLink.cc
        LogReplayLink.h
        LogReplayLinkController.cc
        LogReplayLinkController.h
        MAVLinkProtocol.cc
        MAVLinkProtocol.h
        TCPLink.cc
        TCPLink.h
        UDPLink.cc
        UDPLink.h
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE QABSTRACTSOCKET_DEBUG)

#===========================================================================#

if(QGC_NO_SERIAL_LINK)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE QGC_NO_SERIAL_LINK)
else()
    target_sources(${CMAKE_PROJECT_NAME}
        PRIVATE
            QGCSerialPortInfo.cc
            QGCSerialPortInfo.h
            SerialLink.cc
            SerialLink.h
            UdpIODevice.cc
            UdpIODevice.h
    )

    if(NOT ANDROID AND NOT IOS)
        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Qt6::SerialPort)
    endif()
endif()

#===========================================================================#

if(QGC_ENABLE_BLUETOOTH)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Qt6::Bluetooth)
    target_sources(${CMAKE_PROJECT_NAME}
        PRIVATE
            BluetoothLink.cc
            BluetoothLink.h
    )
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE QGC_ENABLE_BLUETOOTH)
endif()

#===========================================================================#
# OpenSSL PQC Settings (C++ Backend for QML UI)
# Note: Technology demonstration with no dependency on existing communication links
#===========================================================================#
target_sources(${CMAKE_PROJECT_NAME}
    PRIVATE
        PqcTls/OpenSSLPQCSettings.cc
        PqcTls/OpenSSLPQCSettings.h
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/PqcTls)

#===========================================================================#
# [추가] PQC TLS Communication (Post-Quantum Cryptography)
#===========================================================================#
if(ANDROID)
    set(PQC_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/PqcTls)
    set(PQC_SO_FILE_PATH ${PQC_SRC_DIR}/libs/android/${CMAKE_ANDROID_ARCH_ABI}/libpqc_tls_wrapper.so)
    add_library(pqc_tls_wrapper SHARED IMPORTED GLOBAL)
    set_target_properties(pqc_tls_wrapper PROPERTIES
        IMPORTED_LOCATION ${PQC_SO_FILE_PATH}
    )
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE pqc_tls_wrapper)
    
    # APK 내부에 .so 파일을 포함시키도록 지시
    set_property(TARGET ${CMAKE_PROJECT_NAME} APPEND PROPERTY QT_ANDROID_EXTRA_LIBS ${PQC_SO_FILE_PATH})
    
    # C-Wrapper 헤더파일을 위한 include 경로 추가
    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${PQC_SRC_DIR})
endif()

#===========================================================================#

if(QGC_ZEROCONF_ENABLED)
    CPMAddPackage(
        NAME qmdnsengine
        GITHUB_REPOSITORY nitroshare/qmdnsengine
        GIT_TAG master
        OPTIONS
            "BUILD_DOC OFF"
            "BUILD_EXAMPLES OFF"
            "BUILD_TESTS OFF"
    )

    if(TARGET qmdnsengine)
        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE qmdnsengine)
        target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE QGC_ZEROCONF_ENABLED)
    endif()
endif()

#===========================================================================#

add_subdirectory(AirLink)
add_subdirectory(MockLink)
