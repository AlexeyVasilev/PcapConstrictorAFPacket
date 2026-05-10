#include "config/ConfigLoader.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace pcap_constrictor_afpacket {

namespace {

std::string Trim(std::string_view text) {
    std::size_t begin = 0;
    while (begin < text.size() &&
           std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }

    std::size_t end = text.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }

    return std::string(text.substr(begin, end - begin));
}

std::string ToLower(std::string_view text) {
    std::string lowered(text);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return lowered;
}

std::string StripInlineComment(std::string_view text) {
    for (std::size_t index = 0; index < text.size(); ++index) {
        const char ch = text[index];
        if ((ch == ';' || ch == '#') &&
            (index == 0 || std::isspace(static_cast<unsigned char>(text[index - 1])) != 0)) {
            return Trim(text.substr(0, index));
        }
    }

    return Trim(text);
}

bool ParseBool(std::string_view value, bool& output) {
    const std::string lowered = ToLower(Trim(value));
    if (lowered == "true" || lowered == "1") {
        output = true;
        return true;
    }

    if (lowered == "false" || lowered == "0") {
        output = false;
        return true;
    }

    return false;
}

bool ParseUint32(std::string_view value, std::uint32_t& output) {
    const std::string trimmed = Trim(value);
    if (trimmed.empty()) {
        return false;
    }

    std::uint32_t parsed_value = 0;
    const auto* begin = trimmed.data();
    const auto* end = trimmed.data() + trimmed.size();
    const auto result = std::from_chars(begin, end, parsed_value);
    if (result.ec != std::errc{} || result.ptr != end) {
        return false;
    }

    output = parsed_value;
    return true;
}

bool ParsePorts(std::string_view value, std::vector<std::uint16_t>& ports) {
    std::vector<std::uint16_t> parsed_ports;
    std::size_t start = 0;

    while (start <= value.size()) {
        const std::size_t comma = value.find(',', start);
        const std::string token =
            Trim(value.substr(start, comma == std::string_view::npos ? value.size() - start
                                                                     : comma - start));

        if (token.empty()) {
            return false;
        }

        std::uint32_t parsed_port = 0;
        if (!ParseUint32(token, parsed_port) || parsed_port > 65535U) {
            return false;
        }

        parsed_ports.push_back(static_cast<std::uint16_t>(parsed_port));

        if (comma == std::string_view::npos) {
            break;
        }

        start = comma + 1;
    }

    ports = std::move(parsed_ports);
    return true;
}

std::string FormatError(std::string_view source_name,
                        std::size_t line_number,
                        std::string_view message) {
    std::ostringstream stream;
    stream << source_name << ':' << line_number << ": " << message;
    return stream.str();
}

bool AssignValue(PolicyConfig& config,
                 std::string_view source_name,
                 std::size_t line_number,
                 std::string_view section,
                 std::string_view key,
                 std::string_view value,
                 std::string& error) {
    const std::string normalized_section = ToLower(section);
    const std::string normalized_key = ToLower(key);

    auto invalid_value = [&](std::string_view details) {
        error = FormatError(source_name, line_number, details);
        return false;
    };

    if (normalized_section == "capture") {
        if (normalized_key == "interface") {
            config.capture.interface = Trim(value);
            return true;
        }

        if (normalized_key == "output") {
            config.capture.output = Trim(value);
            return true;
        }

        std::uint32_t parsed = 0;
        if (!ParseUint32(value, parsed)) {
            return invalid_value("invalid unsigned integer for capture option");
        }

        if (normalized_key == "default_snaplen") {
            config.capture.default_snaplen = parsed;
            return true;
        }

        if (normalized_key == "max_capture_len") {
            config.capture.max_capture_len = parsed;
            return true;
        }

        return invalid_value("unknown key in [capture]");
    }

    if (normalized_section == "tls") {
        if (normalized_key == "enabled") {
            bool parsed = false;
            if (!ParseBool(value, parsed)) {
                return invalid_value("invalid boolean for tls.enabled");
            }
            config.tls.enabled = parsed;
            return true;
        }

        if (normalized_key == "ports") {
            if (!ParsePorts(value, config.tls.ports)) {
                return invalid_value("invalid port list for tls.ports");
            }
            return true;
        }

        std::uint32_t parsed = 0;
        if (!ParseUint32(value, parsed)) {
            return invalid_value("invalid unsigned integer for [tls]");
        }

        if (normalized_key == "app_data_keep_record_bytes") {
            config.tls.app_data_keep_record_bytes = parsed;
            return true;
        }

        if (normalized_key == "app_data_continuation_keep_bytes") {
            config.tls.app_data_continuation_keep_bytes = parsed;
            return true;
        }

        return invalid_value("unknown key in [tls]");
    }

    if (normalized_section == "quic") {
        if (normalized_key == "enabled" ||
            normalized_key == "require_dcid_match" ||
            normalized_key == "allow_short_header_without_known_dcid") {
            bool parsed = false;
            if (!ParseBool(value, parsed)) {
                return invalid_value("invalid boolean for [quic]");
            }

            if (normalized_key == "enabled") {
                config.quic.enabled = parsed;
            } else if (normalized_key == "require_dcid_match") {
                config.quic.require_dcid_match = parsed;
            } else {
                config.quic.allow_short_header_without_known_dcid = parsed;
            }
            return true;
        }

        if (normalized_key == "ports") {
            if (!ParsePorts(value, config.quic.ports)) {
                return invalid_value("invalid port list for quic.ports");
            }
            return true;
        }

        std::uint32_t parsed = 0;
        if (!ParseUint32(value, parsed)) {
            return invalid_value("invalid unsigned integer for [quic]");
        }

        if (normalized_key == "short_header_keep_packet_bytes") {
            config.quic.short_header_keep_packet_bytes = parsed;
            return true;
        }

        return invalid_value("unknown key in [quic]");
    }

    if (normalized_section == "stats") {
        if (normalized_key != "enabled") {
            return invalid_value("unknown key in [stats]");
        }

        bool parsed = false;
        if (!ParseBool(value, parsed)) {
            return invalid_value("invalid boolean for stats.enabled");
        }

        config.stats.enabled = parsed;
        return true;
    }

    error = FormatError(source_name, line_number, "unknown section");
    return false;
}

}  // namespace

ConfigLoadResult ConfigLoader::LoadFromFile(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        return ConfigLoadResult{
            .config = {},
            .error = "unable to open config file: " + path.string(),
        };
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (!input.good() && !input.eof()) {
        return ConfigLoadResult{
            .config = {},
            .error = "failed to read config file: " + path.string(),
        };
    }

    return LoadFromString(buffer.str(), path.string());
}

ConfigLoadResult ConfigLoader::LoadFromString(std::string_view text,
                                              std::string_view source_name) {
    ConfigLoadResult result;
    std::istringstream stream{std::string(text)};
    std::string line;
    std::string current_section;
    std::size_t line_number = 0;

    while (std::getline(stream, line)) {
        ++line_number;

        const std::string cleaned = StripInlineComment(line);
        if (cleaned.empty()) {
            continue;
        }

        if (cleaned.front() == '[') {
            if (cleaned.back() != ']') {
                result.error = FormatError(source_name, line_number, "unterminated section header");
                return result;
            }

            current_section = Trim(std::string_view(cleaned).substr(1, cleaned.size() - 2));
            if (current_section.empty()) {
                result.error = FormatError(source_name, line_number, "empty section name");
                return result;
            }
            continue;
        }

        const std::size_t equals = cleaned.find('=');
        if (equals == std::string::npos) {
            result.error = FormatError(source_name, line_number, "expected key = value");
            return result;
        }

        if (current_section.empty()) {
            result.error = FormatError(source_name, line_number, "key/value found before any section");
            return result;
        }

        const std::string key = Trim(std::string_view(cleaned).substr(0, equals));
        const std::string value = Trim(std::string_view(cleaned).substr(equals + 1));

        if (key.empty()) {
            result.error = FormatError(source_name, line_number, "empty key");
            return result;
        }

        if (value.empty()) {
            result.error = FormatError(source_name, line_number, "empty value");
            return result;
        }

        if (!AssignValue(result.config,
                         source_name,
                         line_number,
                         current_section,
                         key,
                         value,
                         result.error)) {
            return result;
        }
    }

    if (result.config.capture.default_snaplen == 0U) {
        result.error = FormatError(source_name, 0U, "capture.default_snaplen must be greater than 0");
        return result;
    }

    if (result.config.capture.max_capture_len == 0U) {
        result.error = FormatError(source_name, 0U, "capture.max_capture_len must be greater than 0");
        return result;
    }

    return result;
}

}  // namespace pcap_constrictor_afpacket
