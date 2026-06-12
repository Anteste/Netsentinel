#include "LiveCapture.h"

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

namespace
{
struct CaptureContext
{
    LiveCapture::EventHandler onEvent;
};

std::string ipToString(in_addr address)
{
    char buffer[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr)
    {
        return "0.0.0.0";
    }
    return buffer;
}

NetworkEvent baseEvent(const pcap_pkthdr* header, const ip* ipHeader)
{
    NetworkEvent event;
    event.timestampEpoch = static_cast<long long>(header->ts.tv_sec);
    event.timestamp = formatTimestamp(event.timestampEpoch);
    event.sourceIp = ipToString(ipHeader->ip_src);
    event.destinationIp = ipToString(ipHeader->ip_dst);
    event.eventType = "LIVE_PACKET";
    event.metadata["capture_source"] = "pcap";
    event.metadata["packet_length"] = std::to_string(header->len);
    return event;
}

void handlePacket(u_char* userData, const pcap_pkthdr* header, const u_char* packet)
{
    auto* context = reinterpret_cast<CaptureContext*>(userData);
    constexpr int ethernetHeaderLength = 14;

    if (header->caplen < ethernetHeaderLength + sizeof(ip))
    {
        return;
    }

    const auto* ethernetType = reinterpret_cast<const uint16_t*>(packet + 12);
    if (ntohs(*ethernetType) != ETHERTYPE_IP)
    {
        return;
    }

    const auto* ipHeader = reinterpret_cast<const ip*>(packet + ethernetHeaderLength);
    const int ipHeaderLength = ipHeader->ip_hl * 4;
    if (ipHeaderLength < 20 || header->caplen < static_cast<bpf_u_int32>(ethernetHeaderLength + ipHeaderLength))
    {
        return;
    }

    const u_char* transport = packet + ethernetHeaderLength + ipHeaderLength;
    NetworkEvent event = baseEvent(header, ipHeader);

    if (ipHeader->ip_p == IPPROTO_TCP)
    {
        if (header->caplen < static_cast<bpf_u_int32>(ethernetHeaderLength + ipHeaderLength + sizeof(tcphdr)))
        {
            return;
        }
        const auto* tcpHeader = reinterpret_cast<const tcphdr*>(transport);
        event.protocol = Protocol::TCP;
        event.sourcePort = ntohs(tcpHeader->th_sport);
        event.destinationPort = ntohs(tcpHeader->th_dport);
    }
    else if (ipHeader->ip_p == IPPROTO_UDP)
    {
        if (header->caplen < static_cast<bpf_u_int32>(ethernetHeaderLength + ipHeaderLength + sizeof(udphdr)))
        {
            return;
        }
        const auto* udpHeader = reinterpret_cast<const udphdr*>(transport);
        event.protocol = Protocol::UDP;
        event.sourcePort = ntohs(udpHeader->uh_sport);
        event.destinationPort = ntohs(udpHeader->uh_dport);
    }
    else if (ipHeader->ip_p == IPPROTO_ICMP)
    {
        event.protocol = Protocol::ICMP;
        event.sourcePort = 0;
        event.destinationPort = 0;
    }
    else
    {
        return;
    }

    context->onEvent(event);
}

struct PcapHandleDeleter
{
    void operator()(pcap_t* handle) const
    {
        if (handle != nullptr)
        {
            pcap_close(handle);
        }
    }
};
}

LiveCapture::LiveCapture(std::string requestedInterface)
    : interfaceName(resolveInterface(requestedInterface))
{
}

void LiveCapture::capture(int packetCount, const EventHandler& onEvent) const
{
    char errorBuffer[PCAP_ERRBUF_SIZE]{};
    std::unique_ptr<pcap_t, PcapHandleDeleter> handle(
        pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errorBuffer));

    if (!handle)
    {
        throw std::runtime_error("Could not open interface " + interfaceName + ": " + errorBuffer);
    }

    bpf_program filter{};
    if (pcap_compile(handle.get(), &filter, "tcp or udp or icmp", 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        throw std::runtime_error("Could not compile packet filter: " + std::string(pcap_geterr(handle.get())));
    }

    if (pcap_setfilter(handle.get(), &filter) == -1)
    {
        pcap_freecode(&filter);
        throw std::runtime_error("Could not install packet filter: " + std::string(pcap_geterr(handle.get())));
    }
    pcap_freecode(&filter);

    CaptureContext context{onEvent};
    const int result = pcap_loop(handle.get(), packetCount, handlePacket, reinterpret_cast<u_char*>(&context));
    if (result == PCAP_ERROR)
    {
        throw std::runtime_error("Packet capture failed: " + std::string(pcap_geterr(handle.get())));
    }
}

const std::string& LiveCapture::getInterfaceName() const
{
    return interfaceName;
}

std::string LiveCapture::resolveInterface(const std::string& requestedInterface)
{
    if (!requestedInterface.empty() && requestedInterface != "auto")
    {
        return requestedInterface;
    }

    char errorBuffer[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, errorBuffer) == -1)
    {
        throw std::runtime_error("Could not list capture interfaces: " + std::string(errorBuffer));
    }

    std::string selected;
    for (pcap_if_t* device = devices; device != nullptr; device = device->next)
    {
        if (device->name != nullptr && (device->flags & PCAP_IF_LOOPBACK) == 0)
        {
            selected = device->name;
            break;
        }
    }

    pcap_freealldevs(devices);

    if (selected.empty())
    {
        throw std::runtime_error("No non-loopback capture interface found");
    }

    return selected;
}
