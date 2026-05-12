#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include "recording_writer.h"

bool valid_wav(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    char riff[4]{};
    char wave[4]{};
    file.read(riff, 4);
    file.seekg(8, std::ios::beg);
    file.read(wave, 4);
    return std::string(riff, 4) == "RIFF" && std::string(wave, 4) == "WAVE" &&
           std::filesystem::file_size(path) > 44;
}

int main() {
    const auto root = std::filesystem::temp_directory_path() / "jam_recording_writer_self_test";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);

    RecordingWriter writer;
    if (!writer.start(48000, root)) {
        std::cerr << "failed to start writer\n";
        return 2;
    }

    float samples[120]{};
    for (size_t i = 0; i < 120; ++i) {
        samples[i] = (i % 2 == 0) ? 0.25F : -0.25F;
    }

    writer.enqueue(RecordingWriter::TrackKind::Master, 0, 48000, samples, 120);
    writer.enqueue(RecordingWriter::TrackKind::Self, 0, 48000, samples, 120);
    writer.enqueue(RecordingWriter::TrackKind::Participant, 42, 48000, samples, 120);
    writer.stop();

    const std::filesystem::path folder = writer.folder();
    const bool ok = valid_wav(folder / "master_mix.wav") && valid_wav(folder / "self.wav") &&
                    valid_wav(folder / "user_42.wav");
    std::filesystem::remove_all(root, ec);

    if (!ok) {
        std::cerr << "recording writer did not create valid wav files\n";
        return 3;
    }

    std::cout << "recording_writer_self_test=ok\n";
    return 0;
}
