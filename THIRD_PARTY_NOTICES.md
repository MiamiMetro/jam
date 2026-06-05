# Third-Party Notices

This project uses third-party open-source components.

This file is an inventory and notice summary. It is not a substitute for preserving the full upstream license and copyright texts. Release packaging must include or preserve each dependency's upstream license files and notices from fetched or vendored sources.

## JUCE

JUCE is used for cross-platform audio device access.

- Project: https://juce.com/
- Source: https://github.com/juce-framework/JUCE
- License: AGPLv3 or commercial JUCE license, depending on distribution terms.

This project uses JUCE under AGPLv3-compatible public open-source terms.

## ASIO

ASIO is a Steinberg audio driver technology. This task does not directly bundle ASIO SDK source. JUCE may expose ASIO devices when ASIO support is configured and user-installed ASIO drivers are available.

- Steinberg developer information: https://www.steinberg.net/developers/
- ASIO open-source information: https://www.steinberg.net/developers/asiosdk-open/

ASIO is a trademark and software technology of Steinberg Media Technologies GmbH.

If ASIO SDK or source is bundled later, that distribution must follow Steinberg's applicable ASIO licensing path and notices.

## Asio

Asio is used as a standalone C++ networking library.

- Source: https://github.com/chriskohlhoff/asio
- License: Boost Software License 1.0.

## Opus

Opus is used for compressed audio mode.

- Project: https://opus-codec.org/
- Source: https://github.com/xiph/opus
- License: BSD 3-Clause.

## concurrentqueue

concurrentqueue is used for lock-free concurrent queue data structures.

- Source: https://github.com/cameron314/concurrentqueue
- License: Simplified BSD.

## PicoSHA2

PicoSHA2 is used for SHA-256 hashing.

- Source: https://github.com/okdshin/PicoSHA2
- License: MIT.

## Dear ImGui

Dear ImGui is used for the native client UI.

- Source: https://github.com/ocornut/imgui
- License: MIT.

## GLFW

GLFW is used for window and OpenGL context management.

- Source: https://github.com/glfw/glfw
- License: zlib/libpng.

## spdlog

spdlog is used for logging.

- Source: https://github.com/gabime/spdlog
- License: MIT.
