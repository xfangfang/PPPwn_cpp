#include <iostream>
#include <sstream>

#include <IPv6Layer.h>
#include <Packet.h>
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

#include "exploit.h"

#define SESSION_ID 0xffff

class MyPPPoETagBuilder : public pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder {
public:
    explicit MyPPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPoETagTypes tagType, const uint8_t *recValue,
                               size_t recValueLen) :
            pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(tagType) {
        this->init(static_cast<uint16_t>(tagType), recValue, recValueLen);
    }
};

void PacketBuilder::hexPrint(const pcpp::Packet &packet) {
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

pcpp::Packet PacketBuilder::PADO(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
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

pcpp::Packet PacketBuilder::PADS(const pcpp::MacAddress &source_mac, const pcpp::MacAddress &target_mac,
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