#include "EventSimulator.h"

#include <algorithm>
#include <chrono>

EventSimulator::EventSimulator(const IdsConfig& configValue)
    : config(configValue)
{
}

std::vector<NetworkEvent> EventSimulator::generateEvents() const
{
    std::vector<NetworkEvent> events;
    const auto now = std::chrono::system_clock::now();
    const auto baseEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    const int normalCount = std::max(10, config.simulationEventCount / 2);
    for (int i = 0; i < normalCount; ++i)
    {
        const long long epoch = baseEpoch + i;
        if (i % 3 == 0)
        {
            events.push_back(makeUdpEvent(epoch, "192.168.1." + std::to_string(20 + (i % 8)),
                "192.168.1.1", 40000 + i, 53));
        }
        else
        {
            const int port = (i % 2 == 0) ? 443 : 80;
            events.push_back(makeTcpEvent(epoch, "192.168.1." + std::to_string(30 + (i % 10)),
                "192.168.1.10", 41000 + i, port));
        }
    }

    for (int i = 0; i < config.portScanPortThreshold; ++i)
    {
        events.push_back(makeTcpEvent(baseEpoch + normalCount + i,
            "192.168.1.80", "192.168.1.10", 50000 + i, 20 + i));
    }

    for (int i = 0; i < config.sshBruteForceAttemptThreshold; ++i)
    {
        events.push_back(makeTcpEvent(baseEpoch + normalCount + config.portScanPortThreshold + i,
            "192.168.1.50", "192.168.1.10", 51000 + i, config.sshPort, "SSH_CONNECTION"));
    }

    std::sort(events.begin(), events.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.timestampEpoch < rhs.timestampEpoch;
    });

    return events;
}

NetworkEvent EventSimulator::makeTcpEvent(long long epoch, const std::string& sourceIp,
    const std::string& destinationIp, int sourcePort, int destinationPort,
    const std::string& eventType) const
{
    NetworkEvent event;
    event.timestampEpoch = epoch;
    event.timestamp = formatTimestamp(epoch);
    event.sourceIp = sourceIp;
    event.destinationIp = destinationIp;
    event.sourcePort = sourcePort;
    event.destinationPort = destinationPort;
    event.protocol = Protocol::TCP;
    event.eventType = eventType;
    event.metadata["simulated"] = "true";
    return event;
}

NetworkEvent EventSimulator::makeUdpEvent(long long epoch, const std::string& sourceIp,
    const std::string& destinationIp, int sourcePort, int destinationPort) const
{
    NetworkEvent event;
    event.timestampEpoch = epoch;
    event.timestamp = formatTimestamp(epoch);
    event.sourceIp = sourceIp;
    event.destinationIp = destinationIp;
    event.sourcePort = sourcePort;
    event.destinationPort = destinationPort;
    event.protocol = Protocol::UDP;
    event.eventType = "CONNECTION";
    event.metadata["simulated"] = "true";
    return event;
}
