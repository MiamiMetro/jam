# Client-specific configuration

include(cmake/common.cmake)

# ============================================================
# Client Dependencies
# ============================================================

FetchContent_Declare(
    juce
    GIT_REPOSITORY https://github.com/juce-framework/JUCE.git
    GIT_TAG        8.0.10
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.92.5-docking
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG        3.4
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(JUCE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(JUCE_BUILD_EXTRAS OFF CACHE BOOL "" FORCE)
set(JUCE_ENABLE_MODULE_SOURCE_GROUPS ON CACHE BOOL "" FORCE)
find_package(OpenGL REQUIRED)

FetchContent_MakeAvailable(juce imgui glfw)

find_path(ASIO_SDK_INCLUDE_DIR iasiodrv.h)
find_path(JACK_INCLUDE_DIR jack/jack.h)
set(JUCE_AUDIO_DEVICE_NATIVE_SDK_OVERRIDES "")
if(WIN32 AND NOT ASIO_SDK_INCLUDE_DIR)
    list(APPEND JUCE_AUDIO_DEVICE_NATIVE_SDK_OVERRIDES
        "$<$<CXX_COMPILER_ID:MSVC>:/DJUCE_ASIO=0>"
        "$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-DJUCE_ASIO=0>"
    )
endif()
if(NOT JACK_INCLUDE_DIR)
    list(APPEND JUCE_AUDIO_DEVICE_NATIVE_SDK_OVERRIDES
        "$<$<CXX_COMPILER_ID:MSVC>:/DJUCE_JACK=0>"
        "$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-DJUCE_JACK=0>"
    )
endif()
if(JUCE_AUDIO_DEVICE_NATIVE_SDK_OVERRIDES)
    set_source_files_properties(${juce_SOURCE_DIR}/modules/juce_audio_devices/juce_audio_devices.cpp
        PROPERTIES COMPILE_OPTIONS "${JUCE_AUDIO_DEVICE_NATIVE_SDK_OVERRIDES}")
endif()

# ============================================================
# Client Wrappers
# ============================================================

add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(imgui_lib PUBLIC 
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)
target_link_libraries(imgui_lib PUBLIC glfw OpenGL::GL)

# ============================================================
# Client Target
# ============================================================

add_executable(client
    client.cpp
    gui.cpp
    audio_stream.cpp
    juce_audio_backend.cpp
)

target_compile_definitions(client PRIVATE
    JUCE_GLOBAL_MODULE_SETTINGS_INCLUDED=1
    JUCE_ASIO=1
    JUCE_WASAPI=1
    JUCE_DIRECTSOUND=0
    JUCE_JACK=1
    JUCE_ALSA=1
    JUCE_USE_ANDROID_OBOE=1
    JUCE_WEB_BROWSER=0
    JUCE_USE_CURL=0
)

if(ASIO_SDK_INCLUDE_DIR)
    target_include_directories(client PRIVATE ${ASIO_SDK_INCLUDE_DIR})
endif()
if(JACK_INCLUDE_DIR)
    target_include_directories(client PRIVATE ${JACK_INCLUDE_DIR})
endif()

target_link_libraries(client PRIVATE
    asio
    concurrentqueue
    spdlog::spdlog
    opus
    imgui_lib
    juce::juce_audio_devices
    juce::juce_audio_basics
    juce::juce_core
    juce::juce_events
)

