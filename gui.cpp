#include "gui.h"

#include <cmath>
#include <cstdio>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <imgui_internal.h>

// =============================================================================
// JamGui Custom Widgets Implementation (zynlab-style)
// =============================================================================

namespace JamGui {

// Constants for zynlab aesthetic
static constexpr float PI = 3.141592f;

void UvMeter(const char* label, const ImVec2& size, int* value, int v_min, int v_max) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2      pos       = ImGui::GetCursorScreenPos();

    ImGui::InvisibleButton(label, size);

    float step_height = size.y / static_cast<float>(v_max - v_min + 1);
    float y           = pos.y + size.y;
    float hue         = 0.4f;
    float sat         = 0.6f;

    // Draw segmented meter from bottom to top
    for (int i = v_min; i <= v_max; i += 5) {
        // HSV gradient: 0.4 (green/cyan) at bottom to 0.15 (red/orange) at top
        hue = 0.4f - (static_cast<float>(i - v_min) / static_cast<float>(v_max - v_min)) * 0.25f;
        // Saturation: 0.0 (grey) when inactive, 0.6 when active
        sat = (*value < i ? 0.0f : 0.6f);

        float segment_height = step_height * 4.0f;
        float segment_y      = pos.y + size.y - (static_cast<float>(i - v_min) * step_height);

        draw_list->AddRectFilled(ImVec2(pos.x, segment_y),
                                 ImVec2(pos.x + size.x, segment_y - segment_height + 1.0f),
                                 static_cast<ImU32>(ImColor::HSV(hue, sat, 0.6f)));
    }
}

bool Knob(const char* label, float* p_value, float v_min, float v_max, const ImVec2& size,
          const char* tooltip) {
    bool show_label = label[0] != '#' || label[1] != '#';
    if (label[0] == '#' && label[1] == '#') {
        show_label = false;
    }

    ImGuiIO&    io    = ImGui::GetIO();
    ImGuiStyle& style = ImGui::GetStyle();

    ImVec2 s(size.x - 4, size.y - 4);
    float  radius_outer = std::fmin(s.x, s.y) / 2.0f;
    ImVec2 pos          = ImGui::GetCursorScreenPos();
    pos                 = ImVec2(pos.x + 2, pos.y + 2);
    ImVec2 center       = ImVec2(pos.x + radius_outer, pos.y + radius_outer);

    float       line_height = ImGui::GetTextLineHeight();
    ImDrawList* draw_list   = ImGui::GetWindowDrawList();

    float ANGLE_MIN = PI * 0.70f;
    float ANGLE_MAX = PI * 2.30f;

    if (s.x != 0.0f && s.y != 0.0f) {
        center.x = pos.x + (s.x / 2.0f);
        center.y = pos.y + (s.y / 2.0f);
        ImGui::InvisibleButton(
            label, ImVec2(s.x, s.y + (show_label ? line_height + style.ItemInnerSpacing.y : 0)));
    } else {
        ImGui::InvisibleButton(
            label,
            ImVec2(radius_outer * 2,
                   radius_outer * 2 + (show_label ? line_height + style.ItemInnerSpacing.y : 0)));
    }

    bool value_changed = false;
    bool is_active     = ImGui::IsItemActive();
    bool is_hovered    = ImGui::IsItemHovered();

    if (is_active && io.MouseDelta.y != 0.0f) {
        float step = (v_max - v_min) / 200.0f;
        *p_value -= io.MouseDelta.y * step;
        if (*p_value < v_min)
            *p_value = v_min;
        if (*p_value > v_max)
            *p_value = v_max;
        value_changed = true;
    }

    float angle     = ANGLE_MIN + (ANGLE_MAX - ANGLE_MIN) * (*p_value - v_min) / (v_max - v_min);
    float angle_cos = cosf(angle);
    float angle_sin = sinf(angle);

    // Draw filled center circle
    draw_list->AddCircleFilled(center, radius_outer * 0.7f, ImGui::GetColorU32(ImGuiCol_Button),
                               16);

    // Draw background arc
    draw_list->PathArcTo(center, radius_outer, ANGLE_MIN, ANGLE_MAX, 16);
    draw_list->PathStroke(ImGui::GetColorU32(ImGuiCol_FrameBg), false, 3.0f);

    // Draw indicator line from center to edge
    draw_list->AddLine(ImVec2(center.x + angle_cos * (radius_outer * 0.35f),
                              center.y + angle_sin * (radius_outer * 0.35f)),
                       ImVec2(center.x + angle_cos * (radius_outer * 0.7f),
                              center.y + angle_sin * (radius_outer * 0.7f)),
                       ImGui::GetColorU32(ImGuiCol_SliderGrabActive), 2.0f);

    // Draw active arc (value indicator)
    draw_list->PathArcTo(center, radius_outer, ANGLE_MIN, angle + 0.02f, 16);
    draw_list->PathStroke(ImGui::GetColorU32(ImGuiCol_SliderGrabActive), false, 3.0f);

    // Draw label below knob
    if (show_label) {
        auto textSize = ImGui::CalcTextSize(label);
        draw_list->AddText(ImVec2(pos.x + ((size.x / 2) - (textSize.x / 2)),
                                  pos.y + radius_outer * 2 + style.ItemInnerSpacing.y),
                           ImGui::GetColorU32(ImGuiCol_Text), label);
    }

    // Tooltip on hover
    if (is_active || is_hovered) {
        ImGui::SetNextWindowPos(
            ImVec2(pos.x - style.WindowPadding.x,
                   pos.y - (line_height * 2) - style.ItemInnerSpacing.y - style.WindowPadding.y));
        ImGui::BeginTooltip();
        if (tooltip != nullptr) {
            ImGui::Text("%s\nValue: %.3f", tooltip, static_cast<double>(*p_value));
        } else if (show_label) {
            ImGui::Text("%s %.3f", label, static_cast<double>(*p_value));
        } else {
            ImGui::Text("%.3f", static_cast<double>(*p_value));
        }
        ImGui::EndTooltip();
    }

    return value_changed;
}

bool Fader(const char* label, const ImVec2& size, int* v, int v_min, int v_max, const char* format,
           float power) {
    ImGuiDataType data_type = ImGuiDataType_S32;
    ImGuiWindow*  window    = ImGui::GetCurrentWindow();
    if (window->SkipItems)
        return false;

    ImGuiContext&     g     = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID     id    = window->GetID(label);

    const ImVec2 label_size   = ImGui::CalcTextSize(label, nullptr, true);
    ImVec2       frame_bb_min = window->DC.CursorPos;
    ImVec2       frame_bb_max = ImVec2(frame_bb_min.x + size.x, frame_bb_min.y + size.y);
    const ImRect frame_bb(frame_bb_min, frame_bb_max);

    float        bb_extra_x = label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f;
    const ImRect bb(frame_bb.Min, ImVec2(frame_bb.Max.x + bb_extra_x, frame_bb.Max.y));

    ImGui::ItemSize(bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(frame_bb, id))
        return false;

    if (format == nullptr)
        format = "%d";

    const bool hovered = ImGui::ItemHoverable(frame_bb, id, ImGuiItemFlags_None);
    if ((hovered && g.IO.MouseClicked[0]) || g.NavActivateId == id) {
        ImGui::SetActiveID(id, window);
        ImGui::SetFocusID(id, window);
        ImGui::FocusWindow(window);
    }

    // Draw frame
    const ImU32 frame_col = ImGui::GetColorU32(g.ActiveId == id    ? ImGuiCol_FrameBgActive
                                               : g.HoveredId == id ? ImGuiCol_FrameBgHovered
                                                                   : ImGuiCol_FrameBg);
    ImGui::RenderNavHighlight(frame_bb, id);
    ImGui::RenderFrame(frame_bb.Min, frame_bb.Max, frame_col, true, g.Style.FrameRounding);

    // Slider behavior
    ImRect     grab_bb;
    const bool value_changed = ImGui::SliderBehavior(frame_bb, id, data_type, v, &v_min, &v_max,
                                                     format, ImGuiSliderFlags_Vertical, &grab_bb);
    if (value_changed)
        ImGui::MarkItemEdited(id);

    // Draw gutter (center line)
    ImRect gutter;
    gutter.Min = grab_bb.Min;
    gutter.Max = ImVec2(frame_bb.Max.x - 2.0f, frame_bb.Max.y - 2.0f);
    float w    = ((gutter.Max.x - gutter.Min.x) - 4.0f) / 2.0f;
    gutter.Min.x += w;
    gutter.Max.x -= w;
    window->DrawList->AddRectFilled(gutter.Min, gutter.Max,
                                    ImGui::GetColorU32(ImGuiCol_ButtonActive), style.GrabRounding);

    // Render grab handle
    window->DrawList->AddRectFilled(grab_bb.Min, grab_bb.Max, ImGui::GetColorU32(ImGuiCol_Text),
                                    style.GrabRounding);

    // Display value
    char value_buf[64];
    std::snprintf(value_buf, sizeof(value_buf), format, static_cast<int>(*v * power));
    const char* value_buf_end = value_buf + strlen(value_buf);
    ImGui::RenderTextClipped(ImVec2(frame_bb.Min.x, frame_bb.Min.y + style.FramePadding.y),
                             frame_bb.Max, value_buf, value_buf_end, nullptr, ImVec2(0.5f, 0.0f));

    if (label_size.x > 0.0f)
        ImGui::RenderText(ImVec2(frame_bb.Max.x + style.ItemInnerSpacing.x,
                                 frame_bb.Min.y + style.FramePadding.y),
                          label);

    return value_changed;
}

bool TextCentered(const ImVec2& size, const char* label) {
    ImGuiStyle& style     = ImGui::GetStyle();
    ImVec2      pos       = ImGui::GetCursorScreenPos();
    ImDrawList* draw_list = ImGui::GetWindowDrawList();

    auto result   = ImGui::InvisibleButton(label, size);
    auto textSize = ImGui::CalcTextSize(label);
    draw_list->AddText(
        ImVec2(pos.x + ((size.x / 2) - (textSize.x / 2)), pos.y + style.ItemInnerSpacing.y),
        ImGui::GetColorU32(ImGuiCol_Text), label);

    return result;
}

void ShowTooltipOnHover(const char* tooltip) {
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("%s", tooltip);
        ImGui::EndTooltip();
    }
}

bool ToggleButton(const char* str_id, bool* v, const ImVec2& size) {
    bool   value_change = false;
    ImVec2 pos          = ImGui::GetCursorScreenPos();

    ImDrawList* draw_list = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton(str_id, size);
    if (ImGui::IsItemClicked()) {
        *v           = !*v;
        value_change = true;
    }

    ImU32 col_tint = ImGui::GetColorU32(
        (*v ? ImGui::GetColorU32(ImGuiCol_Text) : ImGui::GetColorU32(ImGuiCol_Border)));
    ImU32 col_bg = ImGui::GetColorU32(ImGui::GetColorU32(ImGuiCol_WindowBg));
    if (ImGui::IsItemHovered()) {
        col_bg = ImGui::GetColorU32(ImGuiCol_ButtonHovered);
    }
    if (ImGui::IsItemActive() || *v) {
        col_bg = ImGui::GetColorU32(ImGuiCol_Button);
    }

    draw_list->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y),
                             ImGui::GetColorU32(col_bg));

    auto textSize = ImGui::CalcTextSize(str_id);
    draw_list->AddText(ImVec2(pos.x + (size.x - textSize.x) / 2, pos.y + (size.y - textSize.y) / 2),
                       col_tint, str_id);

    return value_change;
}

void ApplyZynlabTheme() {
    ImGui::StyleColorsDark();

    ImGuiStyle& style = ImGui::GetStyle();

    // Zynlab spacing
    style.ItemSpacing      = ImVec2(5, 10);
    style.FramePadding     = ImVec2(4, 4);
    style.ItemInnerSpacing = ImVec2(4, 4);
    style.WindowPadding    = ImVec2(8, 8);

    // Zynlab colors - dark blue-gray theme
    ImVec4* colors = style.Colors;

    // Background colors
    colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.14f, 1.00f);
    colors[ImGuiCol_ChildBg]  = ImVec4(0.08f, 0.08f, 0.12f, 1.00f);
    colors[ImGuiCol_PopupBg]  = ImVec4(0.12f, 0.12f, 0.16f, 0.94f);

    // Frame colors
    colors[ImGuiCol_FrameBg]        = ImVec4(0.20f, 0.20f, 0.28f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.28f, 0.28f, 0.38f, 1.00f);
    colors[ImGuiCol_FrameBgActive]  = ImVec4(0.35f, 0.35f, 0.48f, 1.00f);

    // Title bar
    colors[ImGuiCol_TitleBg]          = ImVec4(0.08f, 0.08f, 0.12f, 1.00f);
    colors[ImGuiCol_TitleBgActive]    = ImVec4(0.12f, 0.12f, 0.18f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.08f, 0.08f, 0.12f, 0.75f);

    // Scrollbar
    colors[ImGuiCol_ScrollbarBg]          = ImVec4(0.08f, 0.08f, 0.12f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab]        = ImVec4(0.30f, 0.30f, 0.40f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.40f, 0.40f, 0.52f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.50f, 0.50f, 0.65f, 1.00f);

    // Button colors (will be overridden per-track with HSV)
    colors[ImGuiCol_Button]        = ImVec4(0.25f, 0.38f, 0.52f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.32f, 0.48f, 0.65f, 1.00f);
    colors[ImGuiCol_ButtonActive]  = ImVec4(0.40f, 0.58f, 0.78f, 1.00f);

    // Slider grab
    colors[ImGuiCol_SliderGrab]       = ImVec4(0.40f, 0.55f, 0.70f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.50f, 0.70f, 0.90f, 1.00f);

    // Headers
    colors[ImGuiCol_Header]        = ImVec4(0.22f, 0.30f, 0.40f, 1.00f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.30f, 0.42f, 0.55f, 1.00f);
    colors[ImGuiCol_HeaderActive]  = ImVec4(0.38f, 0.52f, 0.68f, 1.00f);

    // Separator
    colors[ImGuiCol_Separator]        = ImVec4(0.25f, 0.25f, 0.35f, 1.00f);
    colors[ImGuiCol_SeparatorHovered] = ImVec4(0.35f, 0.45f, 0.58f, 1.00f);
    colors[ImGuiCol_SeparatorActive]  = ImVec4(0.45f, 0.58f, 0.72f, 1.00f);

    // Tab
    colors[ImGuiCol_Tab]                = ImVec4(0.18f, 0.22f, 0.30f, 1.00f);
    colors[ImGuiCol_TabHovered]         = ImVec4(0.32f, 0.42f, 0.55f, 1.00f);
    colors[ImGuiCol_TabActive]          = ImVec4(0.25f, 0.35f, 0.48f, 1.00f);
    colors[ImGuiCol_TabUnfocused]       = ImVec4(0.12f, 0.15f, 0.20f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.18f, 0.22f, 0.30f, 1.00f);

    // Docking
    colors[ImGuiCol_DockingPreview] = ImVec4(0.40f, 0.55f, 0.70f, 0.70f);
    colors[ImGuiCol_DockingEmptyBg] = ImVec4(0.08f, 0.08f, 0.12f, 1.00f);

    // Text
    colors[ImGuiCol_Text]         = ImVec4(0.90f, 0.92f, 0.95f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.52f, 0.55f, 1.00f);

    // Check mark
    colors[ImGuiCol_CheckMark] = ImVec4(0.50f, 0.75f, 0.95f, 1.00f);

    // Border
    colors[ImGuiCol_Border]       = ImVec4(0.25f, 0.28f, 0.35f, 1.00f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);

    // Rounding
    style.FrameRounding     = 2.0f;
    style.GrabRounding      = 2.0f;
    style.WindowRounding    = 4.0f;
    style.ChildRounding     = 2.0f;
    style.PopupRounding     = 2.0f;
    style.ScrollbarRounding = 2.0f;
    style.TabRounding       = 2.0f;
}

ImVec4 GetTrackColor(int index, float saturation, float value) {
    // Generate unique hue for each track (zynlab uses 0.05 step)
    float hue = static_cast<float>(index) * 0.08f;
    // Wrap hue to stay in 0-1 range
    hue = hue - static_cast<float>(static_cast<int>(hue));
    return ImColor::HSV(hue, saturation, value);
}

}  // namespace JamGui

// =============================================================================
// Gui Class Implementation
// =============================================================================

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

    // Build initial layout on first frame (auto-dock Jam Client window)
    static bool layout_built = false;
    if (!layout_built) {
        // Build the layout - this will dock "Jam Client" window when it's created
        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dockspace_id, viewport->WorkSize);
        ImGui::DockBuilderDockWindow("Jam Client", dockspace_id);
        ImGui::DockBuilderFinish(dockspace_id);
        layout_built = true;
    }

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
