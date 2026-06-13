cmake_minimum_required(VERSION 3.16)
project(DigitalEvidenceTracker CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── MinGW / GCC flags ─────────────────────────────────────────────
if(MINGW OR (CMAKE_CXX_COMPILER_ID STREQUAL "GNU"))
    add_compile_options(
        -Wno-deprecated-declarations
        -Wno-unused-parameter
    )
endif()

# ── MSVC flags ────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/Zc:__cplusplus /permissive-)
endif()

# ── Qt6 automoc ───────────────────────────────────────────────────
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# ── Source files ──────────────────────────────────────────────────
add_executable(evidence_tracker
    main.cpp
    User.cpp
    Database.cpp
    Evidence.cpp
    EvidenceTracker.cpp
    AuthSystem.cpp
    ReportGenerator.cpp
    EvidenceTrackerGUI.cpp
    resources/resources.qrc
)

# ── Include own headers ───────────────────────────────────────────
target_include_directories(evidence_tracker PRIVATE ${CMAKE_SOURCE_DIR})

# ── Link libraries ────────────────────────────────────────────────
target_link_libraries(evidence_tracker PRIVATE
    Qt6::Widgets
    OpenSSL::Crypto
    OpenSSL::SSL
    SQLite3::SQLite3
)

set_target_properties(evidence_tracker PROPERTIES WIN32_EXECUTABLE TRUE)

if(WIN32)
    target_link_libraries(evidence_tracker PRIVATE ws2_32 crypt32)
endif()

# ── Windows: copy Qt DLLs ─────────────────────────────────────────
if(WIN32)
    add_custom_command(TARGET evidence_tracker POST_BUILD
        COMMAND "${Qt6_DIR}/../../../bin/windeployqt.exe"
                "$<TARGET_FILE:evidence_tracker>"
        COMMENT "Deploying Qt6 runtime DLLs..."
        VERBATIM
    )
endif()
