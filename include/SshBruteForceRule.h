#ifndef IDS_SSH_BRUTE_FORCE_RULE_H
#define IDS_SSH_BRUTE_FORCE_RULE_H

#include "DetectionEngine.h"
#include "IdsConfig.h"

#include <deque>
#include <map>
#include <string>

class SshBruteForceRule : public DetectionRule
{
public:
    explicit SshBruteForceRule(const IdsConfig& config);
    std::optional<Alert> inspect(const NetworkEvent& event, int nextAlertId) override;

private:
    struct Attempt
    {
        long long timestampEpoch{0};
        std::string destinationIp;
    };

    int sshPort;
    int windowSeconds;
    int attemptThreshold;
    Severity severity;
    std::map<std::string, std::deque<Attempt>> attemptsBySource;

    void pruneOldAttempts(const std::string& sourceIp, long long currentEpoch);
};

#endif
