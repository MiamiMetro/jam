#include "ImGuiApp.h"

#include <GL/gl.h>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#ifdef _WIN32
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#include <dwmapi.h>
#include <minwindef.h>
#include <windef.h>
#include <wingdi.h>
#pragma comment(lib, "dwmapi.lib")
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#endif

ImGuiApp* ImGuiApp::s_Instance = nullptr;

ImGuiApp::ImGuiApp(int width, int height, const char* title, bool vsync, int targetFPS)
    : m_Window(nullptr),
      m_IO(nullptr),
      m_VSync(vsync),
      m_TargetFrameTime(targetFPS > 0 ? 1.0 / targetFPS : 0.0),
      m_LastFrameTime(0.0) {
    s_Instance = this;

    // Setup GLFW
    if (glfwInit() == 0) {
        return;
    }

    // GL 3.3 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    // Create window
    m_Window = glfwCreateWindow(width, height, title, nullptr, nullptr);
    if (m_Window == nullptr) {
        glfwTerminate();
        return;
    }

    glfwMakeContextCurrent(m_Window);
    glfwSwapInterval(m_VSync ? 1 : 0);  // Enable/disable vsync based on parameter

    // Enable dark mode for title bar on Windows 11
#ifdef _WIN32
    HWND hwnd = glfwGetWin32Window(m_Window);
    if (hwnd != nullptr) {
        BOOL useDarkMode = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode,
                              sizeof(useDarkMode));
    }
#endif

    // Initialize frame timing
    m_LastFrameTime = glfwGetTime();

    // Setup ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    m_IO        = &io;

    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    // Disable viewports for better performance (re-enable if you need multi-window support)
    // io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    ImGui::StyleColorsDark();

    // When viewports are enabled we tweak WindowRounding/WindowBg
    ImGuiStyle& style = ImGui::GetStyle();
    if ((io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) != 0) {
        style.WindowRounding              = 0.0F;
        style.Colors[ImGuiCol_WindowBg].w = 1.0F;
    }

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(m_Window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Set window size callback for smooth resize
    glfwSetWindowSizeCallback(m_Window, WindowSizeCallback);
    // Set window close callback for cleanup
    glfwSetWindowCloseCallback(m_Window, WindowCloseCallback);
}

ImGuiApp::~ImGuiApp() {
    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    if (m_Window != nullptr) {
        glfwDestroyWindow(m_Window);
    }

    glfwTerminate();
}

void ImGuiApp::Run() {
    if (m_Window == nullptr) {
        return;
    }

    // Main loop
    while (glfwWindowShouldClose(m_Window) == 0) {
        // FPS limiting (if vsync is off and target FPS is set)
        if (!m_VSync && m_TargetFrameTime > 0.0) {
            double currentTime = glfwGetTime();
            double deltaTime   = currentTime - m_LastFrameTime;

            // Calculate how long to wait
            double waitTime = m_TargetFrameTime - deltaTime;
            if (waitTime > 0.0) {
                // Use glfwWaitEventsTimeout for efficient waiting (yields CPU time)
                // Wait for events or timeout, whichever comes first
                glfwWaitEventsTimeout(waitTime);
            } else {
                // We're behind schedule, just poll events quickly
                glfwPollEvents();
            }

            m_LastFrameTime = glfwGetTime();
        } else {
            // VSync is on, just poll events normally
            glfwPollEvents();
        }

        RenderFrame();
    }
}

void ImGuiApp::RenderFrame() {
    // Start ImGui frame
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    // Create fullscreen dockspace
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDocking;
    window_flags |= ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse;
    window_flags |= ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
    window_flags |= ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;
    window_flags |= ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0F);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0F);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0F, 0.0F));

    ImGui::Begin("DockSpace", nullptr, window_flags);
    ImGui::PopStyleVar(3);

    ImGuiID dockspace_id = ImGui::GetID("MyDockSpace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0F, 0.0F), ImGuiDockNodeFlags_None);
    ImGui::End();

    // Call user's draw callback (only if not shutting down)
    if (m_DrawCallback && !m_ShouldStop.load()) {
        m_DrawCallback();
    }

    // Rendering
    ImGui::Render();
    int display_w;
    int display_h;
    glfwGetFramebufferSize(m_Window, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.2F, 0.2F, 0.2F, 1.0F);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    // Update and render platform windows
    if ((m_IO->ConfigFlags & ImGuiConfigFlags_ViewportsEnable) != 0) {
        GLFWwindow* backup_current_context = glfwGetCurrentContext();
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
        glfwMakeContextCurrent(backup_current_context);
    }

    glfwSwapBuffers(m_Window);
}

void ImGuiApp::WindowSizeCallback(GLFWwindow* /*window*/, int /*width*/, int /*height*/) {
    if (s_Instance != nullptr) {
        s_Instance->RenderFrame();
    }
}

void ImGuiApp::WindowCloseCallback(GLFWwindow* window) {
    if (s_Instance != nullptr) {
        // Set flag to stop drawing callbacks
        s_Instance->m_ShouldStop.store(true);

        // Call close callback (stops io_context)
        if (s_Instance->m_CloseCallback) {
            s_Instance->m_CloseCallback();
        }

        // Ensure window is marked for closing
        glfwSetWindowShouldClose(window, GLFW_TRUE);
    }
}

void ImGuiApp::SetTitleBarColor(unsigned int color) {
#ifdef _WIN32
    HWND hwnd = glfwGetWin32Window(m_Window);
    if (hwnd != nullptr) {
        // Convert RGB to BGR (Windows uses BGR format)
        COLORREF bgr_color = RGB((color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF);
        DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &bgr_color, sizeof(bgr_color));
    }
#endif
}
