#ifndef IDS_IDS_CONFIG_H
#define IDS_IDS_CONFIG_H

#include "Alert.h"

#include <string>

struct IdsConfig
{
    int portScanWindowSeconds{10};
    int portScanPortThreshold{10};
    Severity portScanSeverity{Severity::MEDIUM};

    int sshPort{22};
    int sshBruteForceWindowSeconds{30};
    int sshBruteForceAttemptThreshold{15};
    Severity sshBruteForceSeverity{Severity::HIGH};

    std::string logLevel{"INFO"};
    bool ansiColorEnabled{true};
    bool simulationEnabled{true};
    int simulationEventRatePerSecond{5};
    int simulationEventCount{80};
    std::string liveCaptureInterface{"auto"};
    int liveCapturePacketCount{100};
    std::string eventLogPath{"logs/events.log"};
    std::string alertLogPath{"logs/alerts.log"};

    static IdsConfig defaults();
};

class ConfigLoader
{
public:
    static IdsConfig load(const std::string& path);
    static void writeDefaultIfMissing(const std::string& path);
};

#endif
