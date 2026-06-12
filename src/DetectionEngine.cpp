#include "DetectionEngine.h"

void DetectionEngine::addRule(std::unique_ptr<DetectionRule> rule)
{
    rules.push_back(std::move(rule));
}

std::vector<Alert> DetectionEngine::processEvent(const NetworkEvent& event)
{
    ++processedEvents;
    std::vector<Alert> alerts;

    for (auto& rule : rules)
    {
        auto alert = rule->inspect(event, nextAlertId);
        if (alert)
        {
            alerts.push_back(*alert);
            ++nextAlertId;
            ++generatedAlerts;
        }
    }

    return alerts;
}

int DetectionEngine::processedEventCount() const
{
    return processedEvents;
}

int DetectionEngine::generatedAlertCount() const
{
    return generatedAlerts;
}
