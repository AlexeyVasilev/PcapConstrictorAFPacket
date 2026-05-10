cmake_minimum_required(VERSION 3.20)

project(PcapConstrictorAFPacket VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

add_library(PcapConstrictorAFPacketCore STATIC
    src/capture/AfPacketCapture.cpp
    src/config/ConfigLoader.cpp
    src/decode/PacketDecode.cpp
    src/offline/OfflinePacketFeed.cpp
    src/offline/PcapReader.cpp
    src/policy/LiveCapturePolicy.cpp
    src/policy/TlsConstrictor.cpp
    src/writer/PcapWriter.cpp
)

target_include_directories(PcapConstrictorAFPacketCore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(PcapConstrictorAFPacketCore PUBLIC cxx_std_20)

add_executable(PcapConstrictorAFPacket
    src/main.cpp
)

target_link_libraries(PcapConstrictorAFPacket
    PRIVATE
        PcapConstrictorAFPacketCore
)

add_executable(PcapConstrictorAFPacketTests
    tests/AfPacketCaptureTests.cpp
    tests/TestMain.cpp
    tests/ConfigLoaderTests.cpp
    tests/LivePolicyClassificationTests.cpp
    tests/LivePolicySmokeTests.cpp
    tests/OfflinePacketFeedTests.cpp
    tests/PacketDecodeTests.cpp
    tests/PcapReaderTests.cpp
    tests/PcapWriterTests.cpp
    tests/TlsConstrictorTests.cpp
)

target_link_libraries(PcapConstrictorAFPacketTests
    PRIVATE
        PcapConstrictorAFPacketCore
)

if(BUILD_TESTING)
    add_test(NAME PcapConstrictorAFPacketTests COMMAND PcapConstrictorAFPacketTests)
endif()
