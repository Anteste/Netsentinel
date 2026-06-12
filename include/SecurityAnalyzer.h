#ifndef IDS_SECURITY_ANALYZER_H
#define IDS_SECURITY_ANALYZER_H

#include "Alert.h"
#include "NetworkEvent.h"

#include <map>
#include <set>
#include <string>
#include <vector>

struct SourceProfile
{
    std::string sourceIp;
    int score{0};
    int eventCount{0};
    int alertCount{0};
    std::set<int> destinationPorts;
    std::set<std::string> destinationIps;
    std::map<Protocol, int> protocolCounts;
    std::vector<std::string> reasons;
};

class SecurityAnalyzer
{
public:
    void observeEvent(const NetworkEvent& event);
    void observeAlert(const Alert& alert);
    void printSummary(bool useColor) const;

    const std::map<std::string, SourceProfile>& getProfiles() const;
    SourceProfile getProfile(const std::string& sourceIp) const;

private:
    std::map<std::string, SourceProfile> profiles;

    SourceProfile& profileFor(const std::string& sourceIp);
    void addScore(SourceProfile& profile, int points, const std::string& reason);
    static std::string riskLabel(int score);
    static std::string recommendationFor(const SourceProfile& profile);
};

#endif
