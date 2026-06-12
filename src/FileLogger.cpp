#include "FileLogger.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>

FileLogger::FileLogger(std::string eventLogPathValue, std::string alertLogPathValue)
    : eventLogPath(std::move(eventLogPathValue)),
      alertLogPath(std::move(alertLogPathValue))
{
    ensureParentDirectory(eventLogPath);
    ensureParentDirectory(alertLogPath);
}

void FileLogger::logEvent(const NetworkEvent& event) const
{
    std::ofstream file(eventLogPath, std::ios::app);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open event log: " + eventLogPath);
    }
    file << event.toLogLine() << "\n";
}

void FileLogger::logAlert(const Alert& alert) const
{
    std::ofstream file(alertLogPath, std::ios::app);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open alert log: " + alertLogPath);
    }
    file << alert.toLogLine() << "\n";
}

std::vector<Alert> FileLogger::loadAlerts() const
{
    std::vector<Alert> alerts;
    std::ifstream file(alertLogPath);
    if (!file.is_open())
    {
        return alerts;
    }

    std::string line;
    while (std::getline(file, line))
    {
        auto alert = alertFromLogLine(line);
        if (alert)
        {
            alerts.push_back(*alert);
        }
    }

    return alerts;
}

const std::string& FileLogger::getEventLogPath() const
{
    return eventLogPath;
}

const std::string& FileLogger::getAlertLogPath() const
{
    return alertLogPath;
}

void FileLogger::ensureParentDirectory(const std::string& path)
{
    const std::filesystem::path filePath(path);
    const auto parent = filePath.parent_path();
    if (!parent.empty())
    {
        std::filesystem::create_directories(parent);
    }
}
