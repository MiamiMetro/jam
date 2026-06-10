#include "udp_port.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

void require_rejected(const std::string& value) {
    try {
        (void)parse_udp_port(value, "--port");
    } catch (const std::runtime_error&) {
        return;
    }
    std::cerr << "FAIL: expected UDP port value to be rejected: " << value << '\n';
    std::exit(1);
}

}  // namespace

int main() {
    require(parse_udp_port("0", "--port") == 0, "port 0 should be accepted");
    require(parse_udp_port("9999", "--port") == 9999, "normal port should parse");
    require(parse_udp_port("65535", "--port") == 65535, "max UDP port should parse");

    require_rejected("-1");
    require_rejected("65536");
    require_rejected("9999x");
    require_rejected("abc");

    std::cout << "udp port self-test passed\n";
    return 0;
}
