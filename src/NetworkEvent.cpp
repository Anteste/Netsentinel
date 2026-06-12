#include "NetworkEvent.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

std::string protocolToString(Protocol protocol)
{
    switch (protocol)
    {
        case Protocol::TCP:
            return "TCP";
        case Protocol::UDP:
            return "UDP";
        case Protocol::ICMP:
            return "ICMP";
        default:
            return "UNKNOWN";
    }
}

Protocol protocolFromString(const std::string& value)
{
    std::string normalized = value;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::toupper);

    if (normalized == "TCP")
    {
        return Protocol::TCP;
    }
    if (normalized == "UDP")
    {
        return Protocol::UDP;
    }
    if (normalized == "ICMP")
    {
        return Protocol::ICMP;
    }
    return Protocol::UNKNOWN;
}

std::string formatTimestamp(long long epochSeconds)
{
    const std::time_t timeValue = static_cast<std::time_t>(epochSeconds);
    std::tm timeInfo{};

#if defined(_WIN32)
    localtime_s(&timeInfo, &timeValue);
#else
    localtime_r(&timeValue, &timeInfo);
#endif

    std::ostringstream output;
    output << std::put_time(&timeInfo, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

std::string NetworkEvent::toTerminalString() const
{
    std::ostringstream output;
    output << "[EVENT] " << timestamp << " " << sourceIp;
    if (sourcePort > 0)
    {
        output << ":" << sourcePort;
    }
    output << " -> " << destinationIp;
    if (destinationPort > 0)
    {
        output << ":" << destinationPort;
    }
    output << " " << protocolToString(protocol);
    return output.str();
}

std::string NetworkEvent::toLogLine() const
{
    std::ostringstream output;
    output << timestampEpoch << "|"
           << timestamp << "|"
           << sourceIp << "|"
           << destinationIp << "|"
           << sourcePort << "|"
           << destinationPort << "|"
           << protocolToString(protocol) << "|"
           << eventType;

    for (const auto& entry : metadata)
    {
        output << "|" << entry.first << "=" << entry.second;
    }

    return output.str();
}
