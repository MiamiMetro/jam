#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

inline uint16_t parse_udp_port(const std::string& value, const char* option_name) {
    std::size_t consumed = 0;
    unsigned long port = 0;
    try {
        port = std::stoul(value, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error(std::string(option_name) + " must be a UDP port in 0..65535");
    }
    if (consumed != value.size() || port > 65535UL) {
        throw std::runtime_error(std::string(option_name) + " must be a UDP port in 0..65535");
    }
    return static_cast<uint16_t>(port);
}
