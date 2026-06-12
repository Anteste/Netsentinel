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

std::string NetworkEvent::toTerminalString(bool useColor) const
{
    std::ostringstream output;
    output << (useColor ? "\033[34m[EVENT]\033[0m " : "[EVENT] ") << timestamp << " " << sourceIp;
    if (sourcePort > 0)
    {
        output << ":" << sourcePort;
    }
    output << " -> " << destinationIp;
    if (destinationPort > 0)
    {
        output << ":" << destinationPort;
    }
    const std::string protocolText = protocolToString(protocol);
    if (useColor)
    {
        if (protocol == Protocol::TCP)
        {
            output << " \033[36m" << protocolText << "\033[0m";
        }
        else if (protocol == Protocol::UDP)
        {
            output << " \033[32m" << protocolText << "\033[0m";
        }
        else if (protocol == Protocol::ICMP)
        {
            output << " \033[33m" << protocolText << "\033[0m";
        }
        else
        {
            output << " " << protocolText;
        }
    }
    else
    {
        output << " " << protocolText;
    }
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
