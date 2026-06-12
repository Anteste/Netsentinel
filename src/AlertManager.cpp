#include "AlertManager.h"

#include <algorithm>
#include <iostream>
#include <map>

AlertManager::AlertManager(bool useColorValue)
    : useColor(useColorValue)
{
}

void AlertManager::addAlert(const Alert& alert)
{
    alerts.push_back(alert);
}

void AlertManager::printAlert(const Alert& alert) const
{
    std::cout << alert.toTerminalString(useColor) << std::endl;
}

void AlertManager::printAllAlerts() const
{
    if (alerts.empty())
    {
        std::cout << "[INFO] No alerts generated" << std::endl;
        return;
    }

    for (const auto& alert : alerts)
    {
        printAlert(alert);
    }
}

void AlertManager::printStatus(int processedEvents) const
{
    std::map<Severity, int> severityCounts;
    std::map<std::string, int> sourceCounts;

    for (const auto& alert : alerts)
    {
        ++severityCounts[alert.severity];
        ++sourceCounts[alert.sourceIp];
    }

    std::vector<std::pair<std::string, int>> topSources(sourceCounts.begin(), sourceCounts.end());
    std::sort(topSources.begin(), topSources.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second > rhs.second;
    });

    const std::string statusPrefix = useColor ? "\033[36m[STATUS]\033[0m" : "[STATUS]";
    std::cout << "\n" << statusPrefix << " Processed events: " << processedEvents << std::endl;
    std::cout << statusPrefix << " Generated alerts: " << alerts.size() << std::endl;
    std::cout << statusPrefix << " Severity counts: "
              << colorizeSeverity(Severity::LOW, "LOW=" + std::to_string(severityCounts[Severity::LOW]), useColor) << " "
              << colorizeSeverity(Severity::MEDIUM, "MEDIUM=" + std::to_string(severityCounts[Severity::MEDIUM]), useColor) << " "
              << colorizeSeverity(Severity::HIGH, "HIGH=" + std::to_string(severityCounts[Severity::HIGH]), useColor) << " "
              << colorizeSeverity(Severity::CRITICAL, "CRITICAL=" + std::to_string(severityCounts[Severity::CRITICAL]), useColor) << std::endl;

    std::cout << statusPrefix << " Suspicious source IPs:";
    if (topSources.empty())
    {
        std::cout << " none";
    }
    else
    {
        const std::size_t limit = std::min<std::size_t>(topSources.size(), 5);
        for (std::size_t i = 0; i < limit; ++i)
        {
            std::cout << " " << topSources[i].first << "(" << topSources[i].second << ")";
        }
    }
    std::cout << std::endl;
}

int AlertManager::totalAlerts() const
{
    return static_cast<int>(alerts.size());
}

const std::vector<Alert>& AlertManager::getAlerts() const
{
    return alerts;
}
