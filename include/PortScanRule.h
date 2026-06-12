#ifndef IDS_PORT_SCAN_RULE_H
#define IDS_PORT_SCAN_RULE_H

#include "DetectionEngine.h"
#include "IdsConfig.h"

#include <deque>
#include <map>
#include <string>

class PortScanRule : public DetectionRule
{
public:
    explicit PortScanRule(const IdsConfig& config);
    std::optional<Alert> inspect(const NetworkEvent& event, int nextAlertId) override;

private:
    struct Attempt
    {
        long long timestampEpoch{0};
        std::string destinationIp;
        int destinationPort{0};
    };

    int windowSeconds;
    int portThreshold;
    Severity severity;
    std::map<std::string, std::deque<Attempt>> attemptsBySource;

    void pruneOldAttempts(const std::string& sourceIp, long long currentEpoch);
};

#endif
