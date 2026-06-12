#ifndef IDS_DETECTION_ENGINE_H
#define IDS_DETECTION_ENGINE_H

#include "Alert.h"
#include "NetworkEvent.h"

#include <memory>
#include <optional>
#include <vector>

class DetectionRule
{
public:
    virtual ~DetectionRule() = default;
    virtual std::optional<Alert> inspect(const NetworkEvent& event, int nextAlertId) = 0;
};

class DetectionEngine
{
public:
    void addRule(std::unique_ptr<DetectionRule> rule);
    std::vector<Alert> processEvent(const NetworkEvent& event);
    int processedEventCount() const;
    int generatedAlertCount() const;

private:
    std::vector<std::unique_ptr<DetectionRule>> rules;
    int processedEvents{0};
    int generatedAlerts{0};
    int nextAlertId{1};
};

#endif
