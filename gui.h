#pragma once

#include <atomic>
#include <functional>
#include <utility>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

// =============================================================================
// Custom ImGui Widgets (zynlab-style)
// =============================================================================
namespace JamGui {

// UV Meter - Vertical level meter with HSV color gradient (green to red)
// @param label: Widget ID
// @param size: Widget dimensions
// @param value: Current level value (will be clamped to v_min..v_max)
// @param v_min: Minimum value
// @param v_max: Maximum value
void UvMeter(const char* label, const ImVec2& size, int* value, int v_min, int v_max);

// Knob - Rotary control with arc indicator and center line
// @param label: Widget label (use ## prefix to hide)
// @param p_value: Pointer to float value
// @param v_min: Minimum value
// @param v_max: Maximum value
// @param size: Widget dimensions
// @param tooltip: Optional tooltip text
// @returns: true if value changed
bool Knob(const char* label, float* p_value, float v_min, float v_max, const ImVec2& size,
          const char* tooltip = nullptr);

// Fader - Vertical slider with gutter styling and value display
// @param label: Widget ID
// @param size: Widget dimensions
// @param v: Pointer to int value
// @param v_min: Minimum value
// @param v_max: Maximum value
// @param format: Printf format for value display (default "%d")
// @param power: Value scaling power (default 1.0)
// @returns: true if value changed
bool Fader(const char* label, const ImVec2& size, int* v, int v_min, int v_max,
           const char* format = nullptr, float power = 1.0f);

// TextCentered - Centered text within a fixed area (clickable)
// @param size: Area dimensions
// @param label: Text to display
// @returns: true if clicked
bool TextCentered(const ImVec2& size, const char* label);

// ShowTooltipOnHover - Show tooltip when item is hovered
// @param tooltip: Tooltip text
void ShowTooltipOnHover(const char* tooltip);

// ToggleButton - Toggle button with on/off state
// @param str_id: Button ID/label
// @param v: Pointer to bool state
// @param size: Button dimensions
// @returns: true if state changed
bool ToggleButton(const char* str_id, bool* v, const ImVec2& size);

// Apply zynlab dark theme to ImGui
void ApplyZynlabTheme();

// Get HSV color for track/participant index
ImVec4 GetTrackColor(int index, float saturation = 0.6f, float value = 0.6f);

}  // namespace JamGui

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
