#ifndef IDS_LIVE_CAPTURE_H
#define IDS_LIVE_CAPTURE_H

#include "NetworkEvent.h"

#include <functional>
#include <string>

class LiveCapture
{
public:
    using EventHandler = std::function<void(const NetworkEvent&)>;

    explicit LiveCapture(std::string interfaceName);

    void capture(int packetCount, const EventHandler& onEvent) const;
    const std::string& getInterfaceName() const;

private:
    std::string interfaceName;

    static std::string resolveInterface(const std::string& requestedInterface);
};

#endif
