#ifndef IDS_NETWORK_EVENT_H
#define IDS_NETWORK_EVENT_H

#include <map>
#include <string>

enum class Protocol
{
    TCP,
    UDP,
    ICMP,
    UNKNOWN
};

struct NetworkEvent
{
    long long timestampEpoch{0};
    std::string timestamp;
    std::string sourceIp;
    std::string destinationIp;
    int sourcePort{0};
    int destinationPort{0};
    Protocol protocol{Protocol::UNKNOWN};
    std::string eventType{"CONNECTION"};
    std::map<std::string, std::string> metadata;

    std::string toTerminalString(bool useColor = true) const;
    std::string toLogLine() const;
};

std::string protocolToString(Protocol protocol);
Protocol protocolFromString(const std::string& value);
std::string formatTimestamp(long long epochSeconds);

#endif
