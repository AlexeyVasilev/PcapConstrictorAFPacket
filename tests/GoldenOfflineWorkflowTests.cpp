#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "config/ConfigLoader.hpp"
#include "offline/OfflinePacketFeed.hpp"
#include "offline/PcapReader.hpp"

#ifndef PCAP_CONSTRICTOR_AFPACKET_SOURCE_DIR
#error "PCAP_CONSTRICTOR_AFPACKET_SOURCE_DIR must be defined by CMake"
#endif

#ifndef PCAP_CONSTRICTOR_AFPACKET_BINARY_DIR
#error "PCAP_CONSTRICTOR_AFPACKET_BINARY_DIR must be defined by CMake"
#endif

#ifndef PCAP_CONSTRICTOR_AFPACKET_EXE_PATH
#error "PCAP_CONSTRICTOR_AFPACKET_EXE_PATH must be defined by CMake"
#endif

namespace {

int Fail(std::string_view message) {
    std::cerr << "[GoldenOfflineWorkflowTests] " << message << '\n';
    return 1;
}

[[nodiscard]] std::filesystem::path source_dir() {
    return std::filesystem::path{PCAP_CONSTRICTOR_AFPACKET_SOURCE_DIR};
}

[[nodiscard]] std::filesystem::path binary_dir() {
    return std::filesystem::path{PCAP_CONSTRICTOR_AFPACKET_BINARY_DIR};
}

[[nodiscard]] std::string ReadTextFile(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("failed to open file: " + path.string());
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (!input.good() && !input.eof()) {
        throw std::runtime_error("failed to read file: " + path.string());
    }

    return buffer.str();
}

[[nodiscard]] std::string FilterConstrictConfigSections(std::string_view original_text) {
    std::istringstream stream{std::string(original_text)};
    std::ostringstream filtered;
    std::string line;
    std::string current_section;
    bool keep_current_section = false;

    while (std::getline(stream, line)) {
        const auto left = line.find_first_not_of(" \t\r");
        const auto trimmed = left == std::string::npos ? std::string{} : line.substr(left);

        if (!trimmed.empty() && trimmed.front() == '[') {
            const auto right = trimmed.find(']');
            current_section = right == std::string::npos ? std::string{} : trimmed.substr(1, right - 1);
            keep_current_section =
                current_section == "general" ||
                current_section == "tls" ||
                current_section == "quic" ||
                current_section == "stats";

            if (keep_current_section) {
                filtered << line << '\n';
            }
            continue;
        }

        if (keep_current_section) {
            filtered << line << '\n';
        }
    }

    return filtered.str();
}

void compare_files_exact(std::string_view scenario_name,
                         std::string_view stage_name,
                         const std::filesystem::path& expected_path,
                         const std::filesystem::path& actual_path) {
    std::error_code error;
    const auto expected_size = std::filesystem::file_size(expected_path, error);
    if (error) {
        throw std::runtime_error("failed to get expected file size: " + expected_path.string());
    }

    error.clear();
    const auto actual_size = std::filesystem::file_size(actual_path, error);
    if (error) {
        throw std::runtime_error("failed to get actual file size: " + actual_path.string());
    }

    std::ifstream expected(expected_path, std::ios::binary);
    if (!expected.is_open()) {
        throw std::runtime_error("failed to open expected file: " + expected_path.string());
    }

    std::ifstream actual(actual_path, std::ios::binary);
    if (!actual.is_open()) {
        throw std::runtime_error("failed to open actual file: " + actual_path.string());
    }

    std::array<char, 4096> expected_buffer{};
    std::array<char, 4096> actual_buffer{};
    std::uint64_t offset = 0;

    for (;;) {
        expected.read(expected_buffer.data(), static_cast<std::streamsize>(expected_buffer.size()));
        actual.read(actual_buffer.data(), static_cast<std::streamsize>(actual_buffer.size()));

        const auto expected_read = expected.gcount();
        const auto actual_read = actual.gcount();
        const auto chunk_size = std::min(expected_read, actual_read);

        for (std::streamsize index = 0; index < chunk_size; ++index) {
            const auto expected_byte = static_cast<unsigned char>(expected_buffer[static_cast<std::size_t>(index)]);
            const auto actual_byte = static_cast<unsigned char>(actual_buffer[static_cast<std::size_t>(index)]);
            if (expected_byte != actual_byte) {
                std::ostringstream out;
                out << "scenario " << scenario_name
                    << ", stage " << stage_name
                    << ": file mismatch at byte offset " << (offset + static_cast<std::uint64_t>(index))
                    << ", expected path " << expected_path.string()
                    << ", actual path " << actual_path.string()
                    << ", expected size " << expected_size
                    << ", actual size " << actual_size
                    << ", expected byte " << static_cast<unsigned>(expected_byte)
                    << ", actual byte " << static_cast<unsigned>(actual_byte);
                throw std::runtime_error(out.str());
            }
        }

        if (expected_read != actual_read) {
            std::ostringstream out;
            out << "scenario " << scenario_name
                << ", stage " << stage_name
                << ": file size/content mismatch after byte offset " << offset
                << ", expected path " << expected_path.string()
                << ", actual path " << actual_path.string()
                << ", expected size " << expected_size
                << ", actual size " << actual_size;
            throw std::runtime_error(out.str());
        }

        if (expected_read == 0) {
            break;
        }

        offset += static_cast<std::uint64_t>(expected_read);
    }
}

int run_golden_pipeline_test(const std::string_view scenario_name) {
    using namespace pcap_constrictor_afpacket;

    try {
        const auto scenario_dir = source_dir() / "tests" / "fixtures" / "golden" / std::string(scenario_name);
        const auto output_dir = binary_dir() / "test-output" / "golden" / std::string(scenario_name);
        std::filesystem::create_directories(output_dir);

        const auto input_path = scenario_dir / "input.pcap";
        const auto expected_constricted = scenario_dir / "constricted.pcap";
        const auto source_config = scenario_dir / "constrict.ini";
        const auto actual_constricted = output_dir / "actual.constricted.pcap";
        const auto generated_config = output_dir / "generated.constrict.ini";

        PcapReader input_reader;
        if (!input_reader.Open(input_path)) {
            throw std::runtime_error("failed to inspect input pcap: " + input_reader.error_message());
        }
        const std::uint32_t input_snaplen = input_reader.global_header().snaplen != 0U
                                                ? input_reader.global_header().snaplen
                                                : 65535U;

        const std::string source_config_text = ReadTextFile(source_config);
        std::ostringstream generated;
        generated << FilterConstrictConfigSections(source_config_text)
                  << "\n[tls]\n"
                  << "app_data_continuation_policy = final_only\n"
                  << "\n[capture]\n"
                  << "default_snaplen = " << input_snaplen << '\n'
                  << "max_capture_len = " << input_snaplen << '\n'
                  << "output = " << actual_constricted.string() << '\n';

        {
            std::ofstream config_output(generated_config, std::ios::binary);
            if (!config_output) {
                throw std::runtime_error("failed to create generated config: " + generated_config.string());
            }
            config_output << generated.str();
        }

        const ConfigLoadResult load_result = ConfigLoader::LoadFromFile(generated_config);
        if (!load_result) {
            throw std::runtime_error("generated config load failed: " + load_result.error);
        }

        const OfflinePacketFeedResult feed_result =
            OfflinePacketFeed::Run(input_path, load_result.config.capture.output, load_result.config);
        if (!feed_result) {
            throw std::runtime_error("offline feed failed: " + feed_result.error);
        }

        compare_files_exact(scenario_name, "constrict", expected_constricted, actual_constricted);
        return 0;
    } catch (const std::exception& exception) {
        return Fail(exception.what());
    }
}

}  // namespace

int RunGoldenOfflineWorkflowTests() {
    int failures = 0;
    failures += run_golden_pipeline_test("tls_test_2");
    failures += run_golden_pipeline_test("quic_test_2");
    failures += run_golden_pipeline_test("ipv6_ipv4_test_1");
    return failures;
}
