#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <string>
#include <PcapLiveDeviceList.h>
#include <clipp.h>
#if defined(__APPLE__)
#include <SystemConfiguration/SystemConfiguration.h>
#endif

#include "exploit.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <mmsystem.h>

void cleanup(int ret) {
    exit(ret);
}

#else

#include <csignal>
#include <unistd.h>

static pid_t pid;

void cleanup(int ret) {
    if (pid > 0) kill(pid, SIGKILL);
    exit(ret);
}

static void signal_handler(int sig_num) {
    signal(sig_num, signal_handler);
    cleanup(sig_num);
}

#endif

std::vector<uint8_t> readBinary(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cout << "[-] Cannot open: " << filename << std::endl;
        return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
        std::cout << "[-] Cannot read: " << filename << std::endl;
        return {};
    }

    return buffer;
}

int startExploit(const std::string &interface, enum FirmwareVersion fw,
                 const std::string &stage1, const std::string &stage2,
                 bool retry) {
    Exploit exploit;
    if (exploit.setFirmwareVersion(fw)) cleanup(1);
    if (exploit.setInterface(interface)) cleanup(1);
    auto stage1_data = readBinary(stage1);
    if (stage1_data.empty()) cleanup(1);
    auto stage2_data = readBinary(stage2);
    if (stage2_data.empty()) cleanup(1);
    exploit.setStage1(std::move(stage1_data));
    exploit.setStage2(std::move(stage2_data));
    exploit.setAutoRetry(retry);
    return exploit.run();
}

void listInterfaces() {
    std::cout << "[+] interfaces: " << std::endl;
#if defined(__APPLE__)
    CFArrayRef interfaces = SCNetworkInterfaceCopyAll();
    if (!interfaces) {
        std::cerr << "[-] Failed to get interfaces" << std::endl;
        exit(1);
    }
    CFIndex serviceCount = CFArrayGetCount(interfaces);
    char buffer[1024];
    for (CFIndex i = 0; i < serviceCount; ++i) {
        auto interface = (SCNetworkInterfaceRef) CFArrayGetValueAtIndex(interfaces, i);
        auto serviceName = SCNetworkInterfaceGetLocalizedDisplayName(interface);
        auto bsdName = SCNetworkInterfaceGetBSDName(interface);
        if (bsdName) {
            CFStringGetCString(bsdName, buffer, sizeof(buffer), kCFStringEncodingUTF8);
            printf("\t%s ", buffer);
            if (serviceName) {
                CFStringGetCString(serviceName, buffer, sizeof(buffer), kCFStringEncodingUTF8);
                printf("%s", buffer);
            }
            printf("\n");
        }
    }
    CFRelease(interfaces);
#else
    std::vector<pcpp::PcapLiveDevice *> devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for (pcpp::PcapLiveDevice *dev: devList) {
        if (dev->getLoopback()) continue;
        std::cout << "\t" << dev->getName() << " " << dev->getDesc() << std::endl;
    }
#endif
    exit(0);
}

enum FirmwareVersion getFirmwareOffset(int fw) {
    std::unordered_map<int, enum FirmwareVersion> fw_choices = {
            {700,  FIRMWARE_700_702},
            {701,  FIRMWARE_700_702},
            {702,  FIRMWARE_700_702},
            {750,  FIRMWARE_750_755},
            {750,  FIRMWARE_750_755},
            {751,  FIRMWARE_750_755},
            {755,  FIRMWARE_750_755},
            {800,  FIRMWARE_800_803},
            {801,  FIRMWARE_800_803},
            {803,  FIRMWARE_800_803},
            {850,  FIRMWARE_850_852},
            {852,  FIRMWARE_850_852},
            {900,  FIRMWARE_900},
            {903,  FIRMWARE_903_904},
            {904,  FIRMWARE_903_904},
            {950,  FIRMWARE_950_960},
            {951,  FIRMWARE_950_960},
            {960,  FIRMWARE_950_960},
            {1000, FIRMWARE_1000_1001},
            {1001, FIRMWARE_1000_1001},
            {1050, FIRMWARE_1050_1071},
            {1070, FIRMWARE_1050_1071},
            {1071, FIRMWARE_1050_1071},
            {1100, FIRMWARE_1100}
    };
    if (fw_choices.count(fw) == 0) return FIRMWARE_UNKNOWN;
    return fw_choices[fw];
}

#define SUPPORTED_FIRMWARE "{700,701,702,750,751,755,800,801,803,850,852,900,903,904,950,951,960,1000,1001,1050,1070,1071,1100}"

int main(int argc, char *argv[]) {
    using namespace clipp;
    std::cout << "[+] PPPwn++ - PlayStation 4 PPPoE RCE by theflow" << std::endl;
    std::string interface, stage1 = "stage1/stage1.bin", stage2 = "stage2/stage2.bin";
    int fw = 1100;
    bool retry = false;

    auto cli = (
            ("network interface" % required("--interface") & value("interface", interface), \
            SUPPORTED_FIRMWARE % option("--fw") & integer("fw", fw), \
            "stage1 binary" % option("--stage1") & value("STAGE1", stage1), \
            "stage2 binary" % option("--stage2") & value("STAGE2", stage2), \
            "automatically retry when fails" % option("-a", "--auto-retry").set(retry)
            ) | \
            "list interfaces" % command("list").call(listInterfaces)
    );

    auto result = parse(argc, argv, cli);
    if (!result) {
        std::cout << make_man_page(cli, "pppwn");
        return 1;
    }

    auto offset = getFirmwareOffset(fw);
    if (offset == FIRMWARE_UNKNOWN) {
        std::cerr << "[-] Invalid firmware version" << std::endl;
        std::cout << make_man_page(cli, "pppwn");
        return 1;
    }

    std::cout << "[+] args: interface=" << interface << " fw=" << fw << " stage1=" << stage1 << " stage2=" << stage2
              << " auto-retry=" << (retry ? "on" : "off") << std::endl;

    int ret = 0;
#ifdef _WIN32
    // todo run LcpEchoHandler
    timeBeginPeriod(1);
    ret = startExploit(interface, offset, stage1, stage2, retry);
    timeEndPeriod(1);
#else
    pid = fork();
    if (pid < 0) {
        std::cerr << "[-] Cannot run LcpEchoHandler" << std::endl;
    } else if (pid == 0) {
        LcpEchoHandler lcp_echo_handler(interface);
        lcp_echo_handler.run();
    } else {
        signal(SIGPIPE, SIG_IGN);
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        signal(SIGKILL, signal_handler);
        ret = startExploit(interface, offset, stage1, stage2, retry);
        kill(pid, SIGKILL);
    }
#endif
    return ret;
}
