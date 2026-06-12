#ifndef IDS_ALERT_MANAGER_H
#define IDS_ALERT_MANAGER_H

#include "Alert.h"

#include <vector>

class AlertManager
{
public:
    explicit AlertManager(bool useColor = true);
    void addAlert(const Alert& alert);
    void printAlert(const Alert& alert) const;
    void printAllAlerts() const;
    void printStatus(int processedEvents) const;
    int totalAlerts() const;
    const std::vector<Alert>& getAlerts() const;

private:
    std::vector<Alert> alerts;
    bool useColor;
};

#endif
