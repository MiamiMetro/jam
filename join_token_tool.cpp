#include <cstdint>
#include <exception>
#include <iostream>
#include <string>

#include "performer_join_token.h"

namespace {

[[noreturn]] void usage(const std::string& reason) {
    throw std::runtime_error(
        reason +
        "\nUsage: join_token_tool --secret <secret> --server-id <id> --room <room> "
        "--profile <profile> [--role performer|listener] [--ttl-ms ms]\n");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::string secret;
        std::string server_id = "local-dev";
        std::string room;
        std::string profile;
        std::string role = "performer";
        int64_t     ttl_ms = 120000;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            auto require_value = [&](const std::string& name) -> std::string {
                if (i + 1 >= argc) {
                    usage(name + " requires a value");
                }
                return argv[++i];
            };

            if (arg == "--secret") {
                secret = require_value(arg);
            } else if (arg == "--server-id") {
                server_id = require_value(arg);
            } else if (arg == "--room") {
                room = require_value(arg);
            } else if (arg == "--profile") {
                profile = require_value(arg);
            } else if (arg == "--role") {
                role = require_value(arg);
            } else if (arg == "--ttl-ms") {
                ttl_ms = std::stoll(require_value(arg));
            } else {
                usage("Unknown argument: " + arg);
            }
        }

        if (secret.empty()) {
            usage("--secret is required");
        }
        if (room.empty()) {
            usage("--room is required");
        }
        if (profile.empty()) {
            usage("--profile is required");
        }
        if (role != "performer" && role != "listener") {
            usage("--role must be performer or listener");
        }

        performer_join_token::Claims claims;
        claims.expires_at_ms = performer_join_token::now_ms() + ttl_ms;
        claims.server_id = server_id;
        claims.room_id = room;
        claims.profile_id = profile;
        claims.role = role;
        claims.nonce = performer_join_token::random_nonce();

        std::cout << performer_join_token::create(claims, secret) << "\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
