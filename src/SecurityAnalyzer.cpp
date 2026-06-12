#include "SecurityAnalyzer.h"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace
{
bool isRiskyPort(int port)
{
    return port == 21 || port == 22 || port == 23 || port == 445 || port == 3389 ||
        port == 5900 || port == 6379 || port == 9200;
}

std::string riskyPortName(int port)
{
    switch (port)
    {
        case 21:
            return "FTP";
        case 22:
            return "SSH";
        case 23:
            return "Telnet";
        case 445:
            return "SMB";
        case 3389:
            return "RDP";
        case 5900:
            return "VNC";
        case 6379:
            return "Redis";
        case 9200:
            return "Elasticsearch";
        default:
            return "risky service";
    }
}

int severityPoints(Severity severity)
{
    switch (severity)
    {
        case Severity::LOW:
            return 15;
        case Severity::MEDIUM:
            return 35;
        case Severity::HIGH:
            return 60;
        case Severity::CRITICAL:
            return 90;
    }
    return 0;
}

std::string colorizeScore(int score, const std::string& text, bool useColor)
{
    if (!useColor)
    {
        return text;
    }
    if (score >= 80)
    {
        return "\033[1;41m" + text + "\033[0m";
    }
    if (score >= 50)
    {
        return "\033[35m" + text + "\033[0m";
    }
    if (score >= 25)
    {
        return "\033[33m" + text + "\033[0m";
    }
    return "\033[32m" + text + "\033[0m";
}
}

void SecurityAnalyzer::observeEvent(const NetworkEvent& event)
{
    if (event.sourceIp.empty())
    {
        return;
    }

    auto& profile = profileFor(event.sourceIp);
    ++profile.eventCount;
    profile.destinationIps.insert(event.destinationIp);
    ++profile.protocolCounts[event.protocol];

    if (event.destinationPort > 0)
    {
        const bool newPort = profile.destinationPorts.insert(event.destinationPort).second;
        if (newPort && isRiskyPort(event.destinationPort))
        {
            addScore(profile, 8, "Contacted " + riskyPortName(event.destinationPort) +
                " service on port " + std::to_string(event.destinationPort));
        }
    }

    if (profile.destinationPorts.size() == 5)
    {
        addScore(profile, 10, "Contacted 5 unique destination ports");
    }
    else if (profile.destinationPorts.size() == 10)
    {
        addScore(profile, 15, "Contacted 10 unique destination ports");
    }

    if (profile.destinationIps.size() == 5)
    {
        addScore(profile, 10, "Contacted 5 unique destination hosts");
    }
}

void SecurityAnalyzer::observeAlert(const Alert& alert)
{
    if (alert.sourceIp.empty())
    {
        return;
    }

    auto& profile = profileFor(alert.sourceIp);
    ++profile.alertCount;
    addScore(profile, severityPoints(alert.severity),
        "Triggered " + severityToString(alert.severity) + " " + alertTypeToString(alert.type) + " alert");
}

void SecurityAnalyzer::printSummary(bool useColor) const
{
    std::vector<SourceProfile> profilesByScore;
    for (const auto& entry : profiles)
    {
        profilesByScore.push_back(entry.second);
    }

    std::sort(profilesByScore.begin(), profilesByScore.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.score == rhs.score)
        {
            return lhs.eventCount > rhs.eventCount;
        }
        return lhs.score > rhs.score;
    });

    const std::string header = useColor ? "\033[1;36m[SECURITY SUMMARY]\033[0m" : "[SECURITY SUMMARY]";
    std::cout << "\n" << header << " Source reputation" << std::endl;

    if (profilesByScore.empty())
    {
        std::cout << header << " No source IPs observed" << std::endl;
        return;
    }

    int printed = 0;
    for (const auto& profile : profilesByScore)
    {
        if (printed == 5)
        {
            break;
        }
        if (profile.score == 0)
        {
            continue;
        }

        const std::string scoreText = "score " + std::to_string(profile.score) +
            " " + riskLabel(profile.score);
        std::cout << "- " << profile.sourceIp << " "
                  << colorizeScore(profile.score, scoreText, useColor)
                  << " | events=" << profile.eventCount
                  << " alerts=" << profile.alertCount
                  << " unique_ports=" << profile.destinationPorts.size()
                  << " unique_hosts=" << profile.destinationIps.size() << std::endl;

        const std::size_t reasonLimit = std::min<std::size_t>(profile.reasons.size(), 3);
        for (std::size_t i = 0; i < reasonLimit; ++i)
        {
            std::cout << "  reason: " << profile.reasons[i] << std::endl;
        }
        std::cout << "  recommendation: " << recommendationFor(profile) << std::endl;
        ++printed;
    }

    if (printed == 0)
    {
        std::cout << header << " No suspicious source IPs found in this run" << std::endl;
    }
}

const std::map<std::string, SourceProfile>& SecurityAnalyzer::getProfiles() const
{
    return profiles;
}

SourceProfile SecurityAnalyzer::getProfile(const std::string& sourceIp) const
{
    const auto found = profiles.find(sourceIp);
    if (found == profiles.end())
    {
        return SourceProfile{};
    }
    return found->second;
}

SourceProfile& SecurityAnalyzer::profileFor(const std::string& sourceIp)
{
    auto& profile = profiles[sourceIp];
    if (profile.sourceIp.empty())
    {
        profile.sourceIp = sourceIp;
    }
    return profile;
}

void SecurityAnalyzer::addScore(SourceProfile& profile, int points, const std::string& reason)
{
    profile.score = std::min(100, profile.score + points);
    if (std::find(profile.reasons.begin(), profile.reasons.end(), reason) == profile.reasons.end())
    {
        profile.reasons.push_back(reason);
    }
}

std::string SecurityAnalyzer::riskLabel(int score)
{
    if (score >= 80)
    {
        return "CRITICAL";
    }
    if (score >= 50)
    {
        return "HIGH";
    }
    if (score >= 25)
    {
        return "MEDIUM";
    }
    return "LOW";
}

std::string SecurityAnalyzer::recommendationFor(const SourceProfile& profile)
{
    if (profile.score >= 80)
    {
        return "Investigate immediately, identify the device, and isolate it if it is unknown.";
    }
    if (profile.score >= 50)
    {
        return "Review this host soon and confirm whether the observed activity is expected.";
    }
    if (profile.score >= 25)
    {
        return "Watch this source and compare it with normal device behavior.";
    }
    return "No urgent action; keep monitoring.";
}
