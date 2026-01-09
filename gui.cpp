#include "gui.h"

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

Gui* Gui::s_instance_ = nullptr;

Gui::Gui(int width, int height, const char* title, bool vsync, int target_fps)
    : window_(nullptr),
      io_(nullptr),
      vsync_(vsync),
      target_frame_time_(target_fps > 0 ? 1.0 / target_fps : 0.0),
      last_frame_time_(0.0) {
    s_instance_ = this;

    // Setup GLFW
    if (glfwInit() == 0) {
        return;
    }

    // GL 3.2 + GLSL 150 (required for macOS)
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);  // Required on macOS
#endif

    // Create window
    window_ = glfwCreateWindow(width, height, title, nullptr, nullptr);
    if (window_ == nullptr) {
        glfwTerminate();
        return;
    }

    glfwMakeContextCurrent(window_);
    glfwSwapInterval(vsync_ ? 1 : 0);  // Enable/disable vsync based on parameter

    // Enable dark mode for title bar on Windows 11
#ifdef _WIN32
    HWND hwnd = glfwGetWin32Window(window_);
    if (hwnd != nullptr) {
        BOOL useDarkMode = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode,
                              sizeof(useDarkMode));
    }
#endif

    // Initialize frame timing
    last_frame_time_ = glfwGetTime();

    // Setup ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io_         = &io;

    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    // Disable viewports for better performance (re-enable if you need multi-window support)
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    ImGui::StyleColorsDark();

    // When viewports are enabled we tweak WindowRounding/WindowBg
    ImGuiStyle& style = ImGui::GetStyle();
    if ((io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) != 0) {
        style.WindowRounding              = 0.0F;
        style.Colors[ImGuiCol_WindowBg].w = 1.0F;
    }

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Set window size callback for smooth resize
    glfwSetWindowSizeCallback(window_, window_size_callback);
    // Set window close callback for cleanup
    glfwSetWindowCloseCallback(window_, window_close_callback);
}

Gui::~Gui() {
    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    if (window_ != nullptr) {
        glfwDestroyWindow(window_);
    }

    glfwTerminate();
}

void Gui::run() {
    if (window_ == nullptr) {
        return;
    }

    // Main loop
    while (glfwWindowShouldClose(window_) == 0) {
        double current_time = glfwGetTime();
        double delta_time   = current_time - last_frame_time_;

        // Calculate wait time based on target frame time
        double wait_time = target_frame_time_ - delta_time;

        if (wait_time > 0.001) {  // Only wait if we have more than 1ms
            // Use glfwWaitEventsTimeout to yield CPU time efficiently
            // This blocks the thread until an event arrives or timeout expires
            glfwWaitEventsTimeout(wait_time);
        } else {
            // We're at or past target frame time, poll events and render
            glfwPollEvents();
        }

        // Check if enough time has passed for next frame
        current_time = glfwGetTime();
        delta_time   = current_time - last_frame_time_;

        if (delta_time >= target_frame_time_) {
            render_frame();
            last_frame_time_ = current_time;
        }
    }
}

void Gui::render_frame() {
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
    if (draw_callback_ && !should_stop_.load()) {
        draw_callback_();
    }

    // Rendering
    ImGui::Render();
    int display_w;
    int display_h;
    glfwGetFramebufferSize(window_, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.2F, 0.2F, 0.2F, 1.0F);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    // Update and render platform windows
    if ((io_->ConfigFlags & ImGuiConfigFlags_ViewportsEnable) != 0) {
        GLFWwindow* backup_current_context = glfwGetCurrentContext();
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
        glfwMakeContextCurrent(backup_current_context);
    }

    glfwSwapBuffers(window_);
}

void Gui::window_size_callback(GLFWwindow* /*window*/, int /*width*/, int /*height*/) {
    if (s_instance_ != nullptr) {
        s_instance_->render_frame();
    }
}

void Gui::window_close_callback(GLFWwindow* window) {
    if (s_instance_ != nullptr) {
        // Set flag to stop drawing callbacks
        s_instance_->should_stop_.store(true);

        // Call close callback (stops io_context)
        if (s_instance_->close_callback_) {
            s_instance_->close_callback_();
        }

        // Ensure window is marked for closing
        glfwSetWindowShouldClose(window, GLFW_TRUE);
    }
}

void Gui::set_title_bar_color(unsigned int color) {
#ifdef _WIN32
    HWND hwnd = glfwGetWin32Window(window_);
    if (hwnd != nullptr) {
        // Convert RGB to BGR (Windows uses BGR format)
        COLORREF bgr_color = RGB((color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF);
        DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &bgr_color, sizeof(bgr_color));
    }
#endif
}
