#include "AlertManager.h"
#include "DetectionEngine.h"
#include "EventSimulator.h"
#include "FileLogger.h"
#include "IdsConfig.h"
#include "LiveCapture.h"
#include "PortScanRule.h"
#include "SshBruteForceRule.h"

#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
struct CliOptions
{
    std::string configPath{"config/ids.conf"};
    bool simulate{false};
    std::string interfaceName;
    int packetCount{0};
    bool showAlerts{false};
    int tailAlerts{0};
    std::optional<AlertType> alertTypeFilter;
    std::optional<Severity> severityFilter;
    std::string sourceFilter;
    bool help{false};
};

void printHelp()
{
    std::cout << "Usage: ./netsentinel [--simulate] [--config PATH]\n"
              << "\n"
              << "Options:\n"
              << "  --interface IFACE Analyze live packets on IFACE, for example en0 or wlan0\n"
              << "  --count N         Stop live capture after N packets\n"
              << "  --simulate       Run defensive simulated network events\n"
              << "  --config PATH    Load configuration from PATH\n"
              << "  --show-alerts    Print stored alerts from the alert log\n"
              << "  --type TYPE      Filter stored alerts by PORT_SCAN or SSH_BRUTE_FORCE\n"
              << "  --severity LEVEL Filter stored alerts by LOW, MEDIUM, HIGH, or CRITICAL\n"
              << "  --source IP      Filter stored alerts by source IP\n"
              << "  --tail-alerts N  Print the last N stored alerts\n"
              << "  --help           Show this help text\n";
}

void printBanner(bool useColor)
{
    const char* banner = R"(░███    ░██               ░██                                        ░██    ░██                      ░██
░████   ░██               ░██                                        ░██                             ░██
░██░██  ░██  ░███████  ░████████  ░███████   ░███████  ░████████  ░████████ ░██░████████   ░███████  ░██
░██ ░██ ░██ ░██    ░██    ░██    ░██        ░██    ░██ ░██    ░██    ░██    ░██░██    ░██ ░██    ░██ ░██
░██  ░██░██ ░█████████    ░██     ░███████  ░█████████ ░██    ░██    ░██    ░██░██    ░██ ░█████████ ░██
░██   ░████ ░██           ░██           ░██ ░██        ░██    ░██    ░██    ░██░██    ░██ ░██        ░██
░██    ░███  ░███████      ░████  ░███████   ░███████  ░██    ░██     ░████ ░██░██    ░██  ░███████  ░██
)";

    if (useColor)
    {
        std::cout << "\033[1;36m" << banner << "\033[0m" << std::endl;
    }
    else
    {
        std::cout << banner << std::endl;
    }
}

CliOptions parseArgs(int argc, char** argv)
{
    CliOptions options;
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--simulate")
        {
            options.simulate = true;
        }
        else if (arg == "--interface")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("--interface requires an interface name");
            }
            options.interfaceName = argv[++i];
        }
        else if (arg == "--count")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("--count requires a number");
            }
            options.packetCount = std::stoi(argv[++i]);
            if (options.packetCount <= 0)
            {
                throw std::runtime_error("--count must be greater than zero");
            }
        }
        else if (arg == "--show-alerts")
        {
            options.showAlerts = true;
        }
        else if (arg == "--type")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("--type requires an alert type");
            }
            auto type = alertTypeFromString(argv[++i]);
            if (!type)
            {
                throw std::runtime_error("Invalid alert type");
            }
            options.alertTypeFilter = *type;
        }
        else if (arg == "--severity")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("--severity requires a severity");
            }
            auto severity = severityFromString(argv[++i]);
            if (!severity)
            {
                throw std::runtime_error("Invalid severity");
            }
            options.severityFilter = *severity;
        }
        else if (arg == "--source")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("--source requires an IP address");
            }
            options.sourceFilter = argv[++i];
        }
        else if (arg == "--tail-alerts")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("--tail-alerts requires a number");
            }
            options.tailAlerts = std::stoi(argv[++i]);
            if (options.tailAlerts <= 0)
            {
                throw std::runtime_error("--tail-alerts must be greater than zero");
            }
            options.showAlerts = true;
        }
        else if (arg == "--config")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("--config requires a path");
            }
            options.configPath = argv[++i];
        }
        else if (arg == "--help" || arg == "-h")
        {
            options.help = true;
        }
        else
        {
            throw std::runtime_error("Unknown option: " + arg);
        }
    }
    return options;
}

std::vector<Alert> applyAlertFilters(std::vector<Alert> alerts, const CliOptions& options)
{
    std::vector<Alert> filtered;
    for (const auto& alert : alerts)
    {
        if (options.alertTypeFilter && alert.type != *options.alertTypeFilter)
        {
            continue;
        }
        if (options.severityFilter && alert.severity != *options.severityFilter)
        {
            continue;
        }
        if (!options.sourceFilter.empty() && alert.sourceIp != options.sourceFilter)
        {
            continue;
        }
        filtered.push_back(alert);
    }

    if (options.tailAlerts > 0 && static_cast<int>(filtered.size()) > options.tailAlerts)
    {
        filtered.erase(filtered.begin(), filtered.end() - options.tailAlerts);
    }

    return filtered;
}

void printStoredAlerts(const FileLogger& logger, const CliOptions& options, bool useColor)
{
    const auto alerts = applyAlertFilters(logger.loadAlerts(), options);
    if (alerts.empty())
    {
        std::cout << "[INFO] No stored alerts matched the selected filters" << std::endl;
        return;
    }

    for (const auto& alert : alerts)
    {
        std::cout << alert.toTerminalString(useColor) << std::endl;
    }
}

void processEvent(const NetworkEvent& event, DetectionEngine& engine,
    AlertManager& alertManager, const FileLogger& logger, bool useColor)
{
    std::cout << event.toTerminalString(useColor) << std::endl;
    logger.logEvent(event);

    const auto alerts = engine.processEvent(event);
    for (const auto& alert : alerts)
    {
        alertManager.addAlert(alert);
        logger.logAlert(alert);
        alertManager.printAlert(alert);
    }
}
}

int main(int argc, char** argv)
{
    try
    {
        const CliOptions options = parseArgs(argc, argv);
        if (options.help)
        {
            printHelp();
            return 0;
        }

        ConfigLoader::writeDefaultIfMissing(options.configPath);
        const IdsConfig config = ConfigLoader::load(options.configPath);

        DetectionEngine engine;
        engine.addRule(std::make_unique<PortScanRule>(config));
        engine.addRule(std::make_unique<SshBruteForceRule>(config));

        const bool useColor = config.ansiColorEnabled;
        AlertManager alertManager(useColor);
        FileLogger logger(config.eventLogPath, config.alertLogPath);

        if (options.showAlerts)
        {
            printStoredAlerts(logger, options, useColor);
            return 0;
        }

        printBanner(useColor);
        std::cout << (useColor ? "\033[1;36m[INFO]\033[0m " : "[INFO] ") << "NetSentinel started" << std::endl;
        std::cout << (useColor ? "\033[36m[INFO]\033[0m " : "[INFO] ") << "Config: " << options.configPath << std::endl;
        std::cout << (useColor ? "\033[36m[INFO]\033[0m " : "[INFO] ") << "Event log: " << logger.getEventLogPath() << std::endl;
        std::cout << (useColor ? "\033[36m[INFO]\033[0m " : "[INFO] ") << "Alert log: " << logger.getAlertLogPath() << std::endl;

        if (options.simulate)
        {
            std::cout << (useColor ? "\033[36m[INFO]\033[0m " : "[INFO] ") << "Running defensive simulation mode" << std::endl;
            EventSimulator simulator(config);
            const auto events = simulator.generateEvents();

            for (const auto& event : events)
            {
                processEvent(event, engine, alertManager, logger, useColor);
            }

            alertManager.printStatus(engine.processedEventCount());
            return 0;
        }

        const std::string interfaceName = options.interfaceName.empty()
            ? config.liveCaptureInterface
            : options.interfaceName;
        const int packetCount = options.packetCount > 0
            ? options.packetCount
            : config.liveCapturePacketCount;

        LiveCapture capture(interfaceName);
        std::cout << (useColor ? "\033[36m[INFO]\033[0m " : "[INFO] ")
                  << "Analyzing live packets on interface " << capture.getInterfaceName()
                  << " for " << packetCount << " packets" << std::endl;
        std::cout << (useColor ? "\033[33m[INFO]\033[0m " : "[INFO] ")
                  << "Live capture may require administrator permissions" << std::endl;

        capture.capture(packetCount, [&](const NetworkEvent& event)
        {
            processEvent(event, engine, alertManager, logger, useColor);
        });

        alertManager.printStatus(engine.processedEventCount());
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[ERROR] " << ex.what() << std::endl;
        return 1;
    }
}
