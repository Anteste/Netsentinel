#ifndef IDS_ALERT_H
#define IDS_ALERT_H

#include <map>
#include <optional>
#include <string>

enum class AlertType
{
    PORT_SCAN,
    SSH_BRUTE_FORCE
};

enum class Severity
{
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct Alert
{
    int id{0};
    long long timestampEpoch{0};
    std::string timestamp;
    AlertType type{AlertType::PORT_SCAN};
    Severity severity{Severity::MEDIUM};
    std::string sourceIp;
    std::string destinationIp;
    std::string description;
    std::map<std::string, std::string> metadata;

    std::string toTerminalString() const;
    std::string toLogLine() const;
};

std::string alertTypeToString(AlertType type);
std::optional<AlertType> alertTypeFromString(const std::string& value);
std::string severityToString(Severity severity);
std::optional<Severity> severityFromString(const std::string& value);
std::optional<Alert> alertFromLogLine(const std::string& line);

#endif
