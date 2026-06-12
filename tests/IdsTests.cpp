#include "DetectionEngine.h"
#include "IdsConfig.h"
#include "PortScanRule.h"
#include "SshBruteForceRule.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace
{
void expect(bool condition, const std::string& message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

NetworkEvent tcpEvent(long long epoch, const std::string& sourceIp, int destinationPort)
{
    NetworkEvent event;
    event.timestampEpoch = epoch;
    event.timestamp = formatTimestamp(epoch);
    event.sourceIp = sourceIp;
    event.destinationIp = "192.168.1.10";
    event.sourcePort = 40000 + static_cast<int>(epoch % 1000);
    event.destinationPort = destinationPort;
    event.protocol = Protocol::TCP;
    return event;
}

IdsConfig smallThresholdConfig()
{
    IdsConfig config;
    config.portScanWindowSeconds = 10;
    config.portScanPortThreshold = 3;
    config.portScanSeverity = Severity::HIGH;
    config.sshPort = 22;
    config.sshBruteForceWindowSeconds = 30;
    config.sshBruteForceAttemptThreshold = 4;
    config.sshBruteForceSeverity = Severity::CRITICAL;
    return config;
}

void testPortScanDetected()
{
    DetectionEngine engine;
    engine.addRule(std::make_unique<PortScanRule>(smallThresholdConfig()));

    expect(engine.processEvent(tcpEvent(1000, "10.0.0.5", 80)).empty(), "first port scan event should not alert");
    expect(engine.processEvent(tcpEvent(1001, "10.0.0.5", 81)).empty(), "second port scan event should not alert");
    const auto alerts = engine.processEvent(tcpEvent(1002, "10.0.0.5", 82));

    expect(alerts.size() == 1, "port scan threshold should create one alert");
    expect(alerts[0].type == AlertType::PORT_SCAN, "port scan alert should have PORT_SCAN type");
    expect(alerts[0].severity == Severity::HIGH, "port scan alert should use configured severity");
    expect(alerts[0].sourceIp == "10.0.0.5", "port scan alert should include source IP");
    expect(alerts[0].metadata.at("unique_ports") == "3", "port scan alert should include unique port count");
}

void testPortScanNotDetectedBelowThreshold()
{
    DetectionEngine engine;
    engine.addRule(std::make_unique<PortScanRule>(smallThresholdConfig()));

    engine.processEvent(tcpEvent(1000, "10.0.0.6", 80));
    const auto alerts = engine.processEvent(tcpEvent(1001, "10.0.0.6", 81));

    expect(alerts.empty(), "port scan should not alert below threshold");
}

void testSshBruteForceDetected()
{
    DetectionEngine engine;
    engine.addRule(std::make_unique<SshBruteForceRule>(smallThresholdConfig()));

    for (int i = 0; i < 3; ++i)
    {
        expect(engine.processEvent(tcpEvent(2000 + i, "10.0.0.7", 22)).empty(),
            "SSH brute force should not alert before threshold");
    }

    const auto alerts = engine.processEvent(tcpEvent(2003, "10.0.0.7", 22));
    expect(alerts.size() == 1, "SSH brute force threshold should create one alert");
    expect(alerts[0].type == AlertType::SSH_BRUTE_FORCE, "SSH alert should have SSH_BRUTE_FORCE type");
    expect(alerts[0].severity == Severity::CRITICAL, "SSH alert should use configured severity");
    expect(alerts[0].metadata.at("attempt_count") == "4", "SSH alert should include attempt count");
    expect(alerts[0].metadata.at("detection_source") == "network_connections",
        "SSH alert should document network-based detection");
}

void testSshBruteForceNotDetectedBelowThreshold()
{
    DetectionEngine engine;
    engine.addRule(std::make_unique<SshBruteForceRule>(smallThresholdConfig()));

    for (int i = 0; i < 3; ++i)
    {
        const auto alerts = engine.processEvent(tcpEvent(3000 + i, "10.0.0.8", 22));
        expect(alerts.empty(), "SSH brute force should not alert below threshold");
    }
}

void testConfigurationLoadsValues()
{
    const std::string path = "/tmp/ids-test-config.conf";
    std::ofstream file(path);
    file << "port_scan_window_seconds=7\n"
         << "port_scan_port_threshold=4\n"
         << "port_scan_severity=LOW\n"
         << "ssh_port=2222\n"
         << "ssh_brute_force_window_seconds=12\n"
         << "ssh_brute_force_attempt_threshold=5\n"
         << "ssh_brute_force_severity=HIGH\n"
         << "log_level=DEBUG\n"
         << "simulation_enabled=false\n"
         << "simulation_event_rate_per_second=2\n"
         << "simulation_event_count=20\n"
         << "event_log_path=logs/test-events.log\n"
         << "alert_log_path=logs/test-alerts.log\n";
    file.close();

    const auto config = ConfigLoader::load(path);
    expect(config.portScanWindowSeconds == 7, "config should load port scan window");
    expect(config.portScanPortThreshold == 4, "config should load port threshold");
    expect(config.portScanSeverity == Severity::LOW, "config should load port scan severity");
    expect(config.sshPort == 2222, "config should load SSH port");
    expect(config.sshBruteForceAttemptThreshold == 5, "config should load SSH threshold");
    expect(config.sshBruteForceSeverity == Severity::HIGH, "config should load SSH severity");
    expect(!config.simulationEnabled, "config should load simulation flag");
    expect(config.eventLogPath == "logs/test-events.log", "config should load event log path");
}
}

int main()
{
    try
    {
        testPortScanDetected();
        testPortScanNotDetectedBelowThreshold();
        testSshBruteForceDetected();
        testSshBruteForceNotDetectedBelowThreshold();
        testConfigurationLoadsValues();
        std::cout << "All IDS tests passed" << std::endl;
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Test failed: " << ex.what() << std::endl;
        return 1;
    }
}
