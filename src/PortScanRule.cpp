#include "PortScanRule.h"

#include <set>
#include <sstream>

PortScanRule::PortScanRule(const IdsConfig& config)
    : windowSeconds(config.portScanWindowSeconds),
      portThreshold(config.portScanPortThreshold),
      severity(config.portScanSeverity)
{
}

std::optional<Alert> PortScanRule::inspect(const NetworkEvent& event, int nextAlertId)
{
    if (event.protocol != Protocol::TCP || event.destinationPort <= 0)
    {
        return std::nullopt;
    }

    auto& attempts = attemptsBySource[event.sourceIp];
    attempts.push_back({event.timestampEpoch, event.destinationIp, event.destinationPort});
    pruneOldAttempts(event.sourceIp, event.timestampEpoch);

    std::set<int> uniquePorts;
    std::set<std::string> destinationIps;
    for (const auto& attempt : attemptsBySource[event.sourceIp])
    {
        uniquePorts.insert(attempt.destinationPort);
        destinationIps.insert(attempt.destinationIp);
    }

    if (static_cast<int>(uniquePorts.size()) < portThreshold)
    {
        return std::nullopt;
    }

    std::ostringstream portSummary;
    int shown = 0;
    for (int port : uniquePorts)
    {
        if (shown > 0)
        {
            portSummary << ",";
        }
        portSummary << port;
        ++shown;
        if (shown == 12 && uniquePorts.size() > 12)
        {
            portSummary << ",...";
            break;
        }
    }

    Alert alert;
    alert.id = nextAlertId;
    alert.timestampEpoch = event.timestampEpoch;
    alert.timestamp = event.timestamp;
    alert.type = AlertType::PORT_SCAN;
    alert.severity = severity;
    alert.sourceIp = event.sourceIp;
    alert.destinationIp = destinationIps.size() == 1 ? *destinationIps.begin() : "multiple";
    alert.description = event.sourceIp + " contacted " + std::to_string(uniquePorts.size()) +
        " unique TCP ports in " + std::to_string(windowSeconds) + "s";
    alert.metadata["unique_ports"] = std::to_string(uniquePorts.size());
    alert.metadata["port_summary"] = portSummary.str();
    alert.metadata["window_seconds"] = std::to_string(windowSeconds);

    attemptsBySource.erase(event.sourceIp);
    return alert;
}

void PortScanRule::pruneOldAttempts(const std::string& sourceIp, long long currentEpoch)
{
    auto& attempts = attemptsBySource[sourceIp];
    while (!attempts.empty() && currentEpoch - attempts.front().timestampEpoch > windowSeconds)
    {
        attempts.pop_front();
    }
}
