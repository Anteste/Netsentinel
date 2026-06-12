#include "Alert.h"

#include <algorithm>
#include <sstream>
#include <vector>

namespace
{
std::string toUpper(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), ::toupper);
    return value;
}

std::vector<std::string> split(const std::string& value, char delimiter)
{
    std::vector<std::string> parts;
    std::stringstream stream(value);
    std::string item;
    while (std::getline(stream, item, delimiter))
    {
        parts.push_back(item);
    }
    return parts;
}
}

std::string alertTypeToString(AlertType type)
{
    switch (type)
    {
        case AlertType::PORT_SCAN:
            return "PORT_SCAN";
        case AlertType::SSH_BRUTE_FORCE:
            return "SSH_BRUTE_FORCE";
    }
    return "PORT_SCAN";
}

std::optional<AlertType> alertTypeFromString(const std::string& value)
{
    const std::string normalized = toUpper(value);
    if (normalized == "PORT_SCAN")
    {
        return AlertType::PORT_SCAN;
    }
    if (normalized == "SSH_BRUTE_FORCE")
    {
        return AlertType::SSH_BRUTE_FORCE;
    }
    return std::nullopt;
}

std::string severityToString(Severity severity)
{
    switch (severity)
    {
        case Severity::LOW:
            return "LOW";
        case Severity::MEDIUM:
            return "MEDIUM";
        case Severity::HIGH:
            return "HIGH";
        case Severity::CRITICAL:
            return "CRITICAL";
    }
    return "MEDIUM";
}

std::optional<Severity> severityFromString(const std::string& value)
{
    const std::string normalized = toUpper(value);
    if (normalized == "LOW")
    {
        return Severity::LOW;
    }
    if (normalized == "MEDIUM")
    {
        return Severity::MEDIUM;
    }
    if (normalized == "HIGH")
    {
        return Severity::HIGH;
    }
    if (normalized == "CRITICAL")
    {
        return Severity::CRITICAL;
    }
    return std::nullopt;
}

std::string Alert::toTerminalString() const
{
    std::ostringstream output;
    output << "[ALERT][" << severityToString(severity) << "]["
           << alertTypeToString(type) << "] " << description;
    return output.str();
}

std::string Alert::toLogLine() const
{
    std::ostringstream output;
    output << id << "|"
           << timestampEpoch << "|"
           << timestamp << "|"
           << alertTypeToString(type) << "|"
           << severityToString(severity) << "|"
           << sourceIp << "|"
           << destinationIp << "|"
           << description;

    for (const auto& entry : metadata)
    {
        output << "|" << entry.first << "=" << entry.second;
    }

    return output.str();
}

std::optional<Alert> alertFromLogLine(const std::string& line)
{
    const auto parts = split(line, '|');
    if (parts.size() < 8)
    {
        return std::nullopt;
    }

    auto type = alertTypeFromString(parts[3]);
    auto severity = severityFromString(parts[4]);
    if (!type || !severity)
    {
        return std::nullopt;
    }

    Alert alert;
    try
    {
        alert.id = std::stoi(parts[0]);
        alert.timestampEpoch = std::stoll(parts[1]);
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }

    alert.timestamp = parts[2];
    alert.type = *type;
    alert.severity = *severity;
    alert.sourceIp = parts[5];
    alert.destinationIp = parts[6];
    alert.description = parts[7];

    for (std::size_t i = 8; i < parts.size(); ++i)
    {
        const auto separator = parts[i].find('=');
        if (separator != std::string::npos)
        {
            alert.metadata[parts[i].substr(0, separator)] = parts[i].substr(separator + 1);
        }
    }

    return alert;
}
