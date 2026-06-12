#ifndef IDS_FILE_LOGGER_H
#define IDS_FILE_LOGGER_H

#include "Alert.h"
#include "NetworkEvent.h"

#include <string>
#include <vector>

class FileLogger
{
public:
    FileLogger(std::string eventLogPath, std::string alertLogPath);

    void logEvent(const NetworkEvent& event) const;
    void logAlert(const Alert& alert) const;
    std::vector<Alert> loadAlerts() const;

    const std::string& getEventLogPath() const;
    const std::string& getAlertLogPath() const;

private:
    std::string eventLogPath;
    std::string alertLogPath;

    static void ensureParentDirectory(const std::string& path);
};

#endif
