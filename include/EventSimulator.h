#ifndef IDS_EVENT_SIMULATOR_H
#define IDS_EVENT_SIMULATOR_H

#include "IdsConfig.h"
#include "NetworkEvent.h"

#include <vector>

class EventSimulator
{
public:
    explicit EventSimulator(const IdsConfig& config);
    std::vector<NetworkEvent> generateEvents() const;

private:
    IdsConfig config;

    NetworkEvent makeTcpEvent(long long epoch, const std::string& sourceIp,
        const std::string& destinationIp, int sourcePort, int destinationPort,
        const std::string& eventType = "CONNECTION") const;
    NetworkEvent makeUdpEvent(long long epoch, const std::string& sourceIp,
        const std::string& destinationIp, int sourcePort, int destinationPort) const;
};

#endif
