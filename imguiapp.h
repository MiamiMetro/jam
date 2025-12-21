#pragma once

#include <atomic>
#include <functional>
#include <utility>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

class ImGuiApp {
public:
    ImGuiApp(int width, int height, const char* title, bool vsync = false, int targetFPS = 60);
    ~ImGuiApp();

    // Set the function that will be called each frame to draw ImGui content
    void SetDrawCallback(std::function<void()> callback) {
        m_DrawCallback = std::move(callback);
    }

    // Set callback to be called when window is about to close
    void SetCloseCallback(std::function<void()> callback) {
        m_CloseCallback = std::move(callback);
    }

    // Set title bar color (Windows 11 only) - RGB format (0xRRGGBB)
    void SetTitleBarColor(unsigned int color);

    // Run the application
    void Run();

private:
    void        RenderFrame();
    static void WindowSizeCallback(GLFWwindow* window, int width, int height);
    static void WindowCloseCallback(GLFWwindow* window);

    GLFWwindow*           m_Window;
    ImGuiIO*              m_IO;
    std::function<void()> m_DrawCallback;
    std::function<void()> m_CloseCallback;
    bool                  m_VSync;
    double                m_TargetFrameTime;
    double                m_LastFrameTime;
    std::atomic<bool>     m_ShouldStop{false};  // Flag to stop drawing after close

    // Static pointer for callback
    static ImGuiApp* s_Instance;
};
