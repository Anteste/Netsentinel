#include "SshBruteForceRule.h"

#include <set>

SshBruteForceRule::SshBruteForceRule(const IdsConfig& config)
    : sshPort(config.sshPort),
      windowSeconds(config.sshBruteForceWindowSeconds),
      attemptThreshold(config.sshBruteForceAttemptThreshold),
      severity(config.sshBruteForceSeverity)
{
}

std::optional<Alert> SshBruteForceRule::inspect(const NetworkEvent& event, int nextAlertId)
{
    if (event.protocol != Protocol::TCP || event.destinationPort != sshPort)
    {
        return std::nullopt;
    }

    auto& attempts = attemptsBySource[event.sourceIp];
    attempts.push_back({event.timestampEpoch, event.destinationIp});
    pruneOldAttempts(event.sourceIp, event.timestampEpoch);

    if (static_cast<int>(attemptsBySource[event.sourceIp].size()) < attemptThreshold)
    {
        return std::nullopt;
    }

    std::set<std::string> destinationIps;
    for (const auto& attempt : attemptsBySource[event.sourceIp])
    {
        destinationIps.insert(attempt.destinationIp);
    }

    const int attemptCount = static_cast<int>(attemptsBySource[event.sourceIp].size());

    Alert alert;
    alert.id = nextAlertId;
    alert.timestampEpoch = event.timestampEpoch;
    alert.timestamp = event.timestamp;
    alert.type = AlertType::SSH_BRUTE_FORCE;
    alert.severity = severity;
    alert.sourceIp = event.sourceIp;
    alert.destinationIp = destinationIps.size() == 1 ? *destinationIps.begin() : "multiple";
    alert.description = event.sourceIp + " attempted " + std::to_string(attemptCount) +
        " SSH connections in " + std::to_string(windowSeconds) + "s";
    alert.metadata["attempt_count"] = std::to_string(attemptCount);
    alert.metadata["ssh_port"] = std::to_string(sshPort);
    alert.metadata["window_seconds"] = std::to_string(windowSeconds);
    alert.metadata["detection_source"] = "network_connections";

    attemptsBySource.erase(event.sourceIp);
    return alert;
}

void SshBruteForceRule::pruneOldAttempts(const std::string& sourceIp, long long currentEpoch)
{
    auto& attempts = attemptsBySource[sourceIp];
    while (!attempts.empty() && currentEpoch - attempts.front().timestampEpoch > windowSeconds)
    {
        attempts.pop_front();
    }
}
