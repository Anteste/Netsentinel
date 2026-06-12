#include "AlertManager.h"

#include <algorithm>
#include <iostream>
#include <map>

void AlertManager::addAlert(const Alert& alert)
{
    alerts.push_back(alert);
}

void AlertManager::printAlert(const Alert& alert) const
{
    std::cout << alert.toTerminalString() << std::endl;
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

    std::cout << "\n[STATUS] Processed events: " << processedEvents << std::endl;
    std::cout << "[STATUS] Generated alerts: " << alerts.size() << std::endl;
    std::cout << "[STATUS] Severity counts: "
              << "LOW=" << severityCounts[Severity::LOW] << " "
              << "MEDIUM=" << severityCounts[Severity::MEDIUM] << " "
              << "HIGH=" << severityCounts[Severity::HIGH] << " "
              << "CRITICAL=" << severityCounts[Severity::CRITICAL] << std::endl;

    std::cout << "[STATUS] Suspicious source IPs:";
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
