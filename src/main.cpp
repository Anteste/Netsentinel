#include "AlertManager.h"
#include "DetectionEngine.h"
#include "EventSimulator.h"
#include "FileLogger.h"
#include "IdsConfig.h"
#include "PortScanRule.h"
#include "SshBruteForceRule.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace
{
struct CliOptions
{
    std::string configPath{"config/ids.conf"};
    bool simulate{false};
    bool help{false};
};

void printHelp()
{
    std::cout << "Usage: ./ids [--simulate] [--config PATH]\n"
              << "\n"
              << "Options:\n"
              << "  --simulate       Run defensive simulated network events\n"
              << "  --config PATH    Load configuration from PATH\n"
              << "  --help           Show this help text\n";
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

        AlertManager alertManager;
        FileLogger logger(config.eventLogPath, config.alertLogPath);

        std::cout << "[INFO] IDS started" << std::endl;
        std::cout << "[INFO] Config: " << options.configPath << std::endl;
        std::cout << "[INFO] Event log: " << logger.getEventLogPath() << std::endl;
        std::cout << "[INFO] Alert log: " << logger.getAlertLogPath() << std::endl;

        if (!options.simulate && !config.simulationEnabled)
        {
            std::cout << "[INFO] Live capture is not implemented yet. Enable simulation mode to run events." << std::endl;
            return 0;
        }

        EventSimulator simulator(config);
        const auto events = simulator.generateEvents();

        for (const auto& event : events)
        {
            std::cout << event.toTerminalString() << std::endl;
            logger.logEvent(event);

            const auto alerts = engine.processEvent(event);
            for (const auto& alert : alerts)
            {
                alertManager.addAlert(alert);
                logger.logAlert(alert);
                alertManager.printAlert(alert);
            }
        }

        alertManager.printStatus(engine.processedEventCount());
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[ERROR] " << ex.what() << std::endl;
        return 1;
    }
}
