#pragma once

#include <atomic>
#include <functional>
#include <utility>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

class Gui {
public:
    Gui(int width, int height, const char* title, bool vsync = false, int target_fps = 60);
    ~Gui();

    // Set the function that will be called each frame to draw ImGui content
    void set_draw_callback(std::function<void()> callback) {
        draw_callback_ = std::move(callback);
    }

    // Set callback to be called when window is about to close
    void set_close_callback(std::function<void()> callback) {
        close_callback_ = std::move(callback);
    }

    // Set title bar color (Windows 11 only) - RGB format (0xRRGGBB)
    void set_title_bar_color(unsigned int color);

    // Run the application
    void run();

private:
    void        render_frame();
    static void window_size_callback(GLFWwindow* window, int width, int height);
    static void window_close_callback(GLFWwindow* window);

    GLFWwindow*           window_;
    ImGuiIO*              io_;
    std::function<void()> draw_callback_;
    std::function<void()> close_callback_;
    bool                  vsync_;
    double                target_frame_time_;
    double                last_frame_time_;
    std::atomic<bool>     should_stop_{false};  // Flag to stop drawing after close

    // Static pointer for callback
    static Gui* s_instance_;
};
