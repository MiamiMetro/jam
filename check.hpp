#pragma once
#include <system_error>
#include <stdexcept>
#include <string_view>

inline void throw_if_err(const std::error_code& ec, std::string_view where) {
    if (ec) throw std::runtime_error(std::string(where) + ": " + ec.message());
}
