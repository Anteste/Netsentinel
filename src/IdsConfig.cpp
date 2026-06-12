#include "IdsConfig.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace
{
std::string trim(const std::string& value)
{
    auto begin = value.begin();
    while (begin != value.end() && std::isspace(static_cast<unsigned char>(*begin)))
    {
        ++begin;
    }

    auto end = value.end();
    while (end != begin && std::isspace(static_cast<unsigned char>(*(end - 1))))
    {
        --end;
    }

    return std::string(begin, end);
}

bool parseBool(const std::string& value)
{
    std::string normalized = value;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    if (normalized == "true" || normalized == "1" || normalized == "yes")
    {
        return true;
    }
    if (normalized == "false" || normalized == "0" || normalized == "no")
    {
        return false;
    }
    throw std::runtime_error("Invalid boolean value: " + value);
}

int parsePositiveInt(const std::string& key, const std::string& value)
{
    const int parsed = std::stoi(value);
    if (parsed <= 0)
    {
        throw std::runtime_error(key + " must be greater than zero");
    }
    return parsed;
}

Severity parseSeverity(const std::string& key, const std::string& value)
{
    auto severity = severityFromString(value);
    if (!severity)
    {
        throw std::runtime_error("Invalid severity for " + key + ": " + value);
    }
    return *severity;
}
}

IdsConfig IdsConfig::defaults()
{
    return IdsConfig{};
}

IdsConfig ConfigLoader::load(const std::string& path)
{
    std::ifstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open configuration file: " + path);
    }

    IdsConfig config = IdsConfig::defaults();
    std::string line;
    int lineNumber = 0;

    while (std::getline(file, line))
    {
        ++lineNumber;
        const auto comment = line.find('#');
        if (comment != std::string::npos)
        {
            line = line.substr(0, comment);
        }

        line = trim(line);
        if (line.empty())
        {
            continue;
        }

        const auto separator = line.find('=');
        if (separator == std::string::npos)
        {
            throw std::runtime_error("Invalid config line " + std::to_string(lineNumber) + ": " + line);
        }

        const std::string key = trim(line.substr(0, separator));
        const std::string value = trim(line.substr(separator + 1));

        if (key == "port_scan_window_seconds")
        {
            config.portScanWindowSeconds = parsePositiveInt(key, value);
        }
        else if (key == "port_scan_port_threshold")
        {
            config.portScanPortThreshold = parsePositiveInt(key, value);
        }
        else if (key == "port_scan_severity")
        {
            config.portScanSeverity = parseSeverity(key, value);
        }
        else if (key == "ssh_port")
        {
            config.sshPort = parsePositiveInt(key, value);
        }
        else if (key == "ssh_brute_force_window_seconds")
        {
            config.sshBruteForceWindowSeconds = parsePositiveInt(key, value);
        }
        else if (key == "ssh_brute_force_attempt_threshold")
        {
            config.sshBruteForceAttemptThreshold = parsePositiveInt(key, value);
        }
        else if (key == "ssh_brute_force_severity")
        {
            config.sshBruteForceSeverity = parseSeverity(key, value);
        }
        else if (key == "log_level")
        {
            config.logLevel = value;
        }
        else if (key == "ansi_color_enabled")
        {
            config.ansiColorEnabled = parseBool(value);
        }
        else if (key == "simulation_enabled")
        {
            config.simulationEnabled = parseBool(value);
        }
        else if (key == "simulation_event_rate_per_second")
        {
            config.simulationEventRatePerSecond = parsePositiveInt(key, value);
        }
        else if (key == "simulation_event_count")
        {
            config.simulationEventCount = parsePositiveInt(key, value);
        }
        else if (key == "live_capture_interface")
        {
            config.liveCaptureInterface = value;
        }
        else if (key == "live_capture_packet_count")
        {
            config.liveCapturePacketCount = parsePositiveInt(key, value);
        }
        else if (key == "event_log_path")
        {
            config.eventLogPath = value;
        }
        else if (key == "alert_log_path")
        {
            config.alertLogPath = value;
        }
        else
        {
            throw std::runtime_error("Unknown configuration key: " + key);
        }
    }

    return config;
}

void ConfigLoader::writeDefaultIfMissing(const std::string& path)
{
    std::ifstream existing(path);
    if (existing.good())
    {
        return;
    }

    std::ofstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not create default configuration file: " + path);
    }

    file << "# IDS configuration\n"
         << "port_scan_window_seconds=10\n"
         << "port_scan_port_threshold=10\n"
         << "port_scan_severity=MEDIUM\n"
         << "ssh_port=22\n"
         << "ssh_brute_force_window_seconds=30\n"
         << "ssh_brute_force_attempt_threshold=15\n"
         << "ssh_brute_force_severity=HIGH\n"
         << "log_level=INFO\n"
         << "ansi_color_enabled=true\n"
         << "simulation_enabled=true\n"
         << "simulation_event_rate_per_second=5\n"
         << "simulation_event_count=80\n"
         << "live_capture_interface=auto\n"
         << "live_capture_packet_count=100\n"
         << "event_log_path=logs/events.log\n"
         << "alert_log_path=logs/alerts.log\n";
}
