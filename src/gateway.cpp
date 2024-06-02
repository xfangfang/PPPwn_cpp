#include <unistd.h>
#include <iostream>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <IPv4Layer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <Packet.h>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <SystemUtils.h>
#include <PPPoELayer.h>
#include <EthLayer.h>
#include <PayloadLayer.h>
#include <EndianPortable.h>

#include "exploit.h"

const static std::string SOURCE_IPV4 = "10.10.12.1";
const static std::string TARGET_IPV4 = "10.10.12.2";
const static std::string PRIMARY_DNS = "62.210.38.117";
const static std::string SECOND_DNS = "0.0.0.0";

#define WAIT_TIME 30

static pcpp::PPPoESessionLayer *getPPPoESessionLayer(const pcpp::Packet &packet, uint16_t pppType) {
    if (!packet.isPacketOfType(pcpp::PPPoESession)) return nullptr;
    auto *pppLayer = packet.getLayerOfType<pcpp::PPPoESessionLayer>();
    if (pppLayer && pppLayer->getPPPNextProtocol() == pppType) return pppLayer;
    return nullptr;
}

static pcpp::PPPoEDiscoveryLayer *getPPPoEDiscoveryLayer(const pcpp::Packet &packet, uint8_t type) {
    if (!packet.isPacketOfType(pcpp::PPPoEDiscovery)) return nullptr;
    auto *layer = packet.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
    if (layer && layer->getPPPoEHeader()->code == type) return layer;
    return nullptr;
}

std::shared_ptr<PortData> PortMap::addMapping(uint16_t realPort, int type) {
    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
        return nullptr;
    }
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) {
        perror("socket");
        return nullptr;
    }

    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&enable), sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        return nullptr;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &len) < 0) {
        perror("getsockname");
        return nullptr;
    }
    uint16_t hostPort = be16toh(addr.sin_port);

    std::lock_guard<std::mutex> lock(map_mutex);
    auto data = std::make_shared<PortData>(realPort, hostPort, fd);
    real2HostMap[realPort] = data;
    host2RealMap[hostPort] = data;

#ifdef DEBUG
    std::cout << "add mapping: " << std::dec << realPort << " -> " << hostPort << " "
              << real2HostMap.size() << "/" << host2RealMap.size() << std::endl;
#endif
    return data;
}

std::shared_ptr<PortData> PortMap::getMapByRealPort(uint16_t realPort) {
    std::lock_guard<std::mutex> lock(map_mutex);
    if (real2HostMap.count(realPort) == 0)
        return nullptr;
    return real2HostMap[realPort];
}

std::shared_ptr<PortData> PortMap::getMapByHostPort(uint16_t hostPort) {
    std::lock_guard<std::mutex> lock(map_mutex);
    if (host2RealMap.count(hostPort) == 0)
        return nullptr;
    return host2RealMap[hostPort];
}

void PortMap::clear() {
    std::lock_guard<std::mutex> lock(map_mutex);
    std::cout << "close " << std::dec << real2HostMap.size() << " sockets." << std::endl;
    for (auto &it: real2HostMap) {
        close(it.second->socketFd);
    }
}

PortMap::~PortMap() {
    this->clear();
}

void PortMap::removeMapping(uint16_t hostPort) {
    std::lock_guard<std::mutex> lock(map_mutex);
    auto it = host2RealMap.find(hostPort);
    if (it == host2RealMap.end()) return;
#ifdef DEBUG
    std::cout << "remove mapping: " << std::dec << it->second->realPort << " -> " << hostPort << " "
              << real2HostMap.size() << "/" << host2RealMap.size() << std::endl;
#endif
    real2HostMap.erase(it->second->realPort);
    host2RealMap.erase(it);
}

Gateway::Gateway(const std::string &iface_ps4, const std::string &iface_net) {
    pcpp::PcapLiveDevice::DeviceConfiguration config;
    config.direction = pcpp::PcapLiveDevice::PCPP_IN;
    config.packetBufferTimeoutMs = 1;

    dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(iface_ps4);
    if (dev == nullptr) {
        std::cerr << "[-] Cannot find interface with name of '" << iface_ps4 << "'" << std::endl;
        exit(1);
    }
    if (!dev->open(config)) {
        std::cerr << "[-] Cannot open device: " << iface_ps4 << std::endl;
        exit(1);
    }

    net_dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(iface_net);
    if (net_dev == nullptr) {
        std::cerr << "[-] Cannot find interface with name of '" << iface_net << "'" << std::endl;
        exit(1);
    }
    config.mode = pcpp::PcapLiveDevice::DeviceMode::Normal;
    if (!net_dev->open(config)) {
        std::cerr << "[-] Cannot open device: " << iface_net << std::endl;
        exit(1);
    }

    std::cout << "[+] ps4 <-> " << iface_ps4 << " <-> " << iface_net << " <-> internet" << std::endl;
    std::cout << "[+] " << TARGET_IPV4 << " <-> " << SOURCE_IPV4 << " <-> " << net_dev->getIPv4Address().toString()
              << " <-> internet" << std::endl;
    std::cout << "[+] gateway: " << net_dev->getDefaultGateway().toString() << std::endl;

    // get gateway mac address
    while (true) {
        // send arp request
        pcpp::Packet arpRequest;
        pcpp::EthLayer ethLayer(net_dev->getMacAddress(), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"), PCPP_ETHERTYPE_ARP);
        pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST,
                                net_dev->getMacAddress(), pcpp::MacAddress::Zero,
                                net_dev->getIPv4Address(), net_dev->getDefaultGateway());

        arpRequest.addLayer(&ethLayer);
        arpRequest.addLayer(&arpLayer);
        arpRequest.computeCalculateFields();
        net_dev->sendPacket(&arpRequest);

        // wait for arp reply
        net_dev->startCaptureBlockingMode([](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {
            auto parsedPacket = pcpp::Packet(packet);
            auto *arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
            if (!arpLayer) return false;
            if (!arpLayer->isReply()) return false;
            auto *self = (Gateway *) cookie;
            if (arpLayer->getSenderIpAddr() == self->net_dev->getDefaultGateway()) {
                std::cout << "[+] gateway mac: " << arpLayer->getSenderMacAddress().toString() << std::endl
                          << std::endl;
                self->gateway_mac = arpLayer->getSenderMacAddress();
                return true;
            }
            return false;
        }, this, 2);
        if (gateway_mac != pcpp::MacAddress::Zero) break;
    }
}

void Gateway::run() {
    // ps4 <- dev <- net_dev <- internet
    net_dev->startCapture([](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {
        auto *self = (Gateway *) cookie;
        auto parsedPacket = pcpp::Packet(packet);
        auto *ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        if (!ethLayer) return;
        auto *ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (!ipv4Layer) return;

        uint8_t protocol = ipv4Layer->getIPv4Header()->protocol;
        switch (protocol) {
            case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP: {
                auto *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                if (!udpLayer) break;
                auto data = self->portMap.getMapByHostPort(udpLayer->getDstPort());
                if (!data) break;

                pcpp::Packet newPacket;
                pcpp::EthLayer newEthLayer(self->dev->getMacAddress(),
                                           self->ps4_mac,
                                           PCPP_ETHERTYPE_IP);
                pcpp::PayloadLayer payloadLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize(), false);
                parsedPacket.detachLayer(ipv4Layer);
                ipv4Layer->setDstIPv4Address(pcpp::IPv4Address(TARGET_IPV4));
                newPacket.addLayer(&newEthLayer);
                newPacket.addLayer(ipv4Layer);
                parsedPacket.detachLayer(udpLayer);
                newPacket.addLayer(udpLayer);
                newPacket.addLayer(&payloadLayer);
                udpLayer->getUdpHeader()->portDst = htobe16(data->realPort);
                udpLayer->calculateChecksum(true);
                ipv4Layer->computeCalculateFields();
                self->dev->sendPacket(&newPacket);

                // todo: Fix multi fragment issue
                self->portMap.removeMapping(udpLayer->getDstPort());
                break;
            }
            case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP: {
                auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                if (!tcpLayer) break;
                auto data = self->portMap.getMapByHostPort(tcpLayer->getDstPort());
                if (!data) break;

                pcpp::Packet newPacket;
                pcpp::EthLayer newEthLayer(self->dev->getMacAddress(),
                                           self->ps4_mac,
                                           PCPP_ETHERTYPE_IP);
                pcpp::PayloadLayer payloadLayer(tcpLayer->getLayerPayload(), tcpLayer->getLayerPayloadSize(), false);
                parsedPacket.detachLayer(ipv4Layer);
                ipv4Layer->setDstIPv4Address(pcpp::IPv4Address(TARGET_IPV4));
                newPacket.addLayer(&newEthLayer);
                newPacket.addLayer(ipv4Layer);
                parsedPacket.detachLayer(tcpLayer);
                newPacket.addLayer(tcpLayer);
                newPacket.addLayer(&payloadLayer);
                tcpLayer->getTcpHeader()->portDst = htobe16(data->realPort);
                tcpLayer->calculateChecksum(true);
                ipv4Layer->computeCalculateFields();
                if (newEthLayer.getLayerPayloadSize() < self->dev->getMtu()) {
                    self->dev->sendPacket(&newPacket);
                } else {
                    uint64_t fragmentSize = self->dev->getMtu();
                    uint64_t offset{};
                    while (offset < ipv4Layer->getLayerPayloadSize()) {
                        pcpp::Packet packetSlice;

                        pcpp::EthLayer ether(newEthLayer);
                        packetSlice.addLayer(&ether);

                        pcpp::IPv4Layer ipLayerSlice(*ipv4Layer);
                        ipLayerSlice.getIPv4Header()->fragmentOffset = htobe16(offset / 8) | htobe16(0x2000);
                        packetSlice.addLayer(&ipLayerSlice);

                        uint8_t *payload = ipv4Layer->getLayerPayload() + offset;
                        uint64_t payloadSize = fragmentSize - ipLayerSlice.getHeaderLen();

                        // last fragment
                        if (offset + fragmentSize >= ipv4Layer->getLayerPayloadSize()) {
                            ipLayerSlice.getIPv4Header()->fragmentOffset = htobe16(offset / 8) & htobe16(0x1FFF);
                            payloadSize = ipv4Layer->getLayerPayloadSize() - offset;
                        }
                        pcpp::PayloadLayer payloadLayerSlice(payload, payloadSize, false);
                        packetSlice.addLayer(&payloadLayerSlice);
                        packetSlice.computeCalculateFields();
                        offset += payloadSize;
                        self->dev->sendPacket(&packetSlice);
                    }
                }

                if (tcpLayer->getTcpHeader()->finFlag) {
                    self->portMap.removeMapping(tcpLayer->getDstPort());
                }
                break;
            }
            default:
                break;
        }
    }, this);

    // ps4 -> dev -> net_dev -> internet
    running = true;
    while (running) {
        dev->startCaptureBlockingMode([](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {
            auto *self = (Gateway *) cookie;
            if (!self->running) return true;
            auto parsedPacket = pcpp::Packet(packet);
            auto *ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
            if (!ethLayer) return !self->running;

            // PPPoE ping
            auto *pppoesLayer = PacketBuilder::getPPPoESessionLayer(parsedPacket, PCPP_PPP_LCP);
            if (pppoesLayer && pppoesLayer->getLayerPayload()[0] == ECHO_REQ) {
                auto &&echoReply = PacketBuilder::lcpEchoReply(ethLayer->getDestMac(), ethLayer->getSourceMac(),
                                                               pppoesLayer->getPPPoEHeader()->sessionId,
                                                               pppoesLayer->getLayerPayload()[1], // id
                                                               le32toh(*(uint32_t *) &pppoesLayer->getLayerPayload()[4])); // magic number
                self->dev->sendPacket(&echoReply);
                return !self->running;
            }

            // PPPoE connect
            auto *pppoedLayer = getPPPoEDiscoveryLayer(parsedPacket, pcpp::PPPoELayer::PPPOE_CODE_PADI);
            if (pppoedLayer) {
                std::cout << "[*] Get PADI..." << std::endl;
                pcpp::PPPoEDiscoveryLayer::PPPoETag tag = pppoedLayer->getFirstTag();
                self->host_uniq = 0;
                while (tag.isNotNull()) {
                    if (tag.getType() == pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ) {
                        self->host_uniq = le64toh(*(uint64_t *) tag.getValue());
                        break;
                    }
                    tag = pppoedLayer->getNextTag(tag);
                }
                if (self->host_uniq == 0) {
                    std::cerr << "[-] No host-uniq tag found in PADI packet" << std::endl;
                    return !self->running;
                }
                if (tag.getDataSize() != sizeof(uint64_t)) {
                    std::cerr << "[-] Invalid host-uniq tag size: " << tag.getDataSize() << std::endl;
                    return !self->running;
                }

                self->ps4_mac = ethLayer->getSourceMac();
                std::string filter = "(ether src " + ethLayer->getSourceMac().toString() + ")";
                self->dev->setFilter(filter);
                return true;
            }

            auto *ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            if (!ipv4Layer) return !self->running;

            // send ps4 packet to gateway
            pcpp::Packet newPacket;
            pcpp::EthLayer newEthLayer(self->net_dev->getMacAddress(),
                                       self->gateway_mac,
                                       PCPP_ETHERTYPE_IP);
            newPacket.addLayer(&newEthLayer);

            // todo: local ip
            // when self->net_dev->getIPv4Address() == ipv4Layer->getDstIPv4Address()
            uint8_t protocol = ipv4Layer->getIPv4Header()->protocol;
            switch (protocol) {
                case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP: {
                    auto *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                    if (!udpLayer) break;
                    // todo: Filter host
                    pcpp::PayloadLayer payloadLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize(),
                                                    false);
                    parsedPacket.detachLayer(ipv4Layer);
                    ipv4Layer->setSrcIPv4Address(self->net_dev->getIPv4Address()); // 联网网卡的IP地址
                    newPacket.addLayer(ipv4Layer);
                    parsedPacket.detachLayer(udpLayer);
                    newPacket.addLayer(udpLayer);
                    newPacket.addLayer(&payloadLayer);

                    auto hostData = self->portMap.getMapByRealPort(udpLayer->getSrcPort());
                    if (!hostData) {
                        hostData = self->portMap.addMapping(udpLayer->getSrcPort(), SOCK_DGRAM);
                    }
                    if (hostData) {
                        udpLayer->getUdpHeader()->portSrc = htobe16(hostData->hostPort);
                    } else {
                        std::cerr << "[-] Cannot find mapping for port: " << std::dec << udpLayer->getSrcPort()
                                  << std::endl;
                    }

                    udpLayer->calculateChecksum(true);
                    ipv4Layer->computeCalculateFields();
                    self->net_dev->sendPacket(&newPacket);
                    break;
                }
                case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP: {
                    auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                    if (!tcpLayer) break;
                    pcpp::PayloadLayer payloadLayer(tcpLayer->getLayerPayload(), tcpLayer->getLayerPayloadSize(),
                                                    false);
                    parsedPacket.detachLayer(ipv4Layer);
                    ipv4Layer->setSrcIPv4Address(self->net_dev->getIPv4Address());
                    newPacket.addLayer(ipv4Layer);
                    parsedPacket.detachLayer(tcpLayer);
                    newPacket.addLayer(tcpLayer);
                    newPacket.addLayer(&payloadLayer);

                    auto hostData = self->portMap.getMapByRealPort(tcpLayer->getSrcPort());
                    if (!hostData) {
                        hostData = self->portMap.addMapping(tcpLayer->getSrcPort(), SOCK_STREAM);
                    }
                    if (hostData) {
                        tcpLayer->getTcpHeader()->portSrc = htobe16(hostData->hostPort);
                    } else {
                        std::cerr << "[-] Cannot find mapping for port: " << std::dec << tcpLayer->getSrcPort()
                                  << std::endl;
                    }

                    tcpLayer->calculateChecksum(true);
                    ipv4Layer->computeCalculateFields();

                    self->net_dev->sendPacket(&newPacket);
                    break;
                }
                default:
#ifdef DEBUG
                    std::cerr << "unsupported protocol: " << (int) protocol << std::endl;
#endif
                    break;
            }
            return !self->running;
        }, this, 0);
        if (!this->running) return;

        if (ppp_negotiation()) continue;
        if (lcp_negotiation()) continue;
        if (ipcp_negotiation()) continue;
        std::cout << "[+] Network is on" << std::endl;
    }

    // todo: socket timeout cleanup
}

void Gateway::stop() {
    running = false;
    net_dev->stopCapture();
    portMap.clear();
}

Gateway::~Gateway() {
    this->stop();
    this->dev->close();
    this->net_dev->close();
}

int Gateway::lcp_negotiation() const {
    std::cout << "[*] Sending LCP configure request..." << std::endl;
    {
        auto &&packet = PacketBuilder::lcpRequest(this->dev->getMacAddress(), this->ps4_mac);
        this->dev->sendPacket(&packet);
    }

    std::cout << "[*] Waiting for LCP configure ACK..." << std::endl;
    if (dev->startCaptureBlockingMode(
            [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                pcpp::Packet parsedPacket(packet);
                auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_LCP);
                if (layer) return layer->getLayerPayload()[0] == CONF_ACK;
                return false;
            }, nullptr, WAIT_TIME) == -1)
        return 1;

    std::cout << "[*] Waiting for LCP configure request..." << std::endl;
    uint8_t lcp_id = 0;
    if (dev->startCaptureBlockingMode(
            [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                pcpp::Packet parsedPacket(packet);
                auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_LCP);
                if (layer) {
                    *((uint8_t *) cookie) = layer->getLayerPayload()[1];
                    return layer->getLayerPayload()[0] == CONF_REQ;
                }
                return false;
            }, &lcp_id, WAIT_TIME) == -1)
        return 1;

    std::cout << "[*] Sending LCP configure ACK..." << std::endl;
    {
        auto &&packet = PacketBuilder::lcpAck(this->dev->getMacAddress(), this->ps4_mac, lcp_id);
        this->dev->sendPacket(&packet);
    }
    return 0;
}

int Gateway::ipcp_negotiation() const {
    std::cout << "[*] Sending IPCP configure request..." << std::endl;
    {
        auto &&packet = PacketBuilder::ipcpRequest(this->dev->getMacAddress(), this->ps4_mac, SOURCE_IPV4);
        this->dev->sendPacket(&packet);
    }

    std::cout << "[*] Waiting for IPCP configure ACK..." << std::endl;
    if (dev->startCaptureBlockingMode(
            [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                pcpp::Packet parsedPacket(packet);
                auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_IPCP);
                if (layer) return layer->getLayerPayload()[0] == CONF_ACK;
                return false;
            }, nullptr, WAIT_TIME) == -1)
        return 1;

    std::cout << "[*] Waiting for IPCP configure request..." << std::endl;
    uint8_t ipcp_id = 0;
    if (dev->startCaptureBlockingMode(
            [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                pcpp::Packet parsedPacket(packet);
                auto *lcp_id = (uint8_t *) cookie;
                auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_IPCP);
                if (layer) {
                    *lcp_id = layer->getLayerPayload()[1];
                    return layer->getLayerPayload()[0] == CONF_REQ;
                }
                return false;
            }, &ipcp_id, WAIT_TIME) == -1)
        return 1;

    std::cout << "[*] Sending IPCP configure NAK..." << std::endl;
    {
        auto &&packet = PacketBuilder::ipcpNak(this->dev->getMacAddress(), this->ps4_mac, ipcp_id, TARGET_IPV4,
                                               PRIMARY_DNS, SECOND_DNS);
        this->dev->sendPacket(&packet);
    }

    std::cout << "[*] Waiting for IPCP configure request..." << std::endl;
    pcpp::Packet cookie;
    if (dev->startCaptureBlockingMode(
            [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                pcpp::Packet parsedPacket(packet, pcpp::PPPoESession);
                auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_IPCP);
                if (layer && layer->getLayerPayload()[0] == CONF_REQ) {
                    *((pcpp::Packet *) cookie) = parsedPacket;
                    return true;
                }
                return false;
            }, &cookie, WAIT_TIME) == -1)
        return 1;

    std::cout << "[*] Sending IPCP configure ACK..." << std::endl;
    {
        auto *layer = getPPPoESessionLayer(cookie, PCPP_PPP_IPCP);
        if (!layer) {
            std::cerr << "[-] No IPCP layer found in packet" << std::endl;
            return 1;
        }
        uint8_t id = layer->getLayerPayload()[1];
        uint8_t *options = layer->getLayerPayload() + 4;
        uint8_t optionLen = layer->getLayerPayload()[5];

        auto &&packet = PacketBuilder::ipcpAck(this->dev->getMacAddress(), this->ps4_mac, id, options, optionLen);
        this->dev->sendPacket(&packet);
    }
    return 0;
}

int Gateway::ppp_negotiation() {
    std::cout << "[*] Sending PADO..." << std::endl;
    {
        auto &&packet = PacketBuilder::pado(this->dev->getMacAddress(), this->ps4_mac,
                                            nullptr, 0,
                                            (uint8_t * ) & host_uniq, sizeof(uint64_t));
        this->dev->sendPacket(&packet);
    }

    std::cout << "[*] Waiting for PADR..." << std::endl;
    if (dev->startCaptureBlockingMode(
            [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                pcpp::Packet parsedPacket(packet);
                auto *layer = getPPPoEDiscoveryLayer(parsedPacket, pcpp::PPPoELayer::PPPOE_CODE_PADR);
                if (layer) return true;
                return false;
            }, nullptr, WAIT_TIME) == -1)
        return 1;

    std::cout << "[*] Sending PADS..." << std::endl;
    {
        auto &&packet = PacketBuilder::pads(this->dev->getMacAddress(), this->ps4_mac,
                                            (uint8_t * ) & host_uniq, sizeof(uint64_t));
        this->dev->sendPacket(&packet);
    }
    return 0;
}
