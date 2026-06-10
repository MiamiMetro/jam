#include "join_reliability.h"
#include "protocol.h"

#include <chrono>
#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

}  // namespace

int main() {
    using namespace std::chrono_literals;

    require(static_cast<int>(CtrlHdr::Cmd::JOIN_ACK) != static_cast<int>(CtrlHdr::Cmd::JOIN),
            "JOIN_ACK must be distinct from JOIN");
    require(static_cast<int>(CtrlHdr::Cmd::JOIN_REQUIRED) != static_cast<int>(CtrlHdr::Cmd::JOIN),
            "JOIN_REQUIRED must be distinct from JOIN");

    join_reliability::State state{1s};
    const auto now = std::chrono::steady_clock::now();

    require(!state.is_join_confirmed(), "new connection should not start confirmed");
    require(!state.can_send_audio(), "audio must be gated before join ack");
    require(state.should_send_join(now), "new connection should send join immediately");

    state.mark_join_sent(now);
    require(!state.should_send_join(now + 500ms), "join retry should respect retry interval");
    require(state.should_send_join(now + 1000ms), "join retry should fire after retry interval");

    state.mark_join_ack(42);
    require(state.is_join_confirmed(), "join ack should confirm connection");
    require(state.can_send_audio(), "audio should be allowed after join ack");
    require(state.participant_id() == 42, "join ack should store participant id");
    require(state.server_capabilities() == 0,
            "legacy join ack should default to no server capabilities");
    require(!state.should_send_join(now + 2s), "confirmed connection should stop join retries");

    state.mark_join_ack(43, AUDIO_CAP_REDUNDANCY);
    require(state.participant_id() == 43, "extended join ack should update participant id");
    require(state.server_supports(AUDIO_CAP_REDUNDANCY),
            "extended join ack should store server capabilities");

    state.mark_join_required();
    require(!state.is_join_confirmed(), "join required should clear confirmation");
    require(!state.can_send_audio(), "join required should gate audio again");
    require(state.participant_id() == 0, "join required should clear participant id");
    require(state.server_capabilities() == 0,
            "join required should clear server capabilities");
    require(state.should_send_join(now + 2s), "join required should trigger immediate rejoin");

    std::cout << "join reliability self-test passed\n";
    return 0;
}
