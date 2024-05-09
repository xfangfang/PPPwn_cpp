# PPPwn c++ [WIP]

This is the C++ rewrite of [PPPwn](https://github.com/TheOfficialFloW/PPPwn), intended to run on small devices such as routers.

> [!CAUTION]
>
> This project is still work in progress and is currently not suitable for daily use.

The failure rate in the first two stages is very high. I think it may be due to the different execution speeds between c++ and python.
Therefore, some parameters need to be adjusted. So I decided to upload the code here first and wait for someone to improve it.
At the same time, I will continue to complete the other stages.

# Nightly build

You can download the latest build from [nightly.link](https://nightly.link/xfangfang/PPPwn_cpp/workflows/ci.yaml/main?status=completed).

For Windows users, you need to install [npcap](https://npcap.com) before run this program.

# Development

I am developing on arm macOS, testing on both my local machine and a router (MT7621).
Although I have cross-compiled executable files for Linux and Windows, I am not sure if their behaviors are consistent
(for example, it seems that waiting for 1ms runs slower on Windows).

The project depends on [pcap++](https://github.com/seladb/PcapPlusPlus), but you don't need to install this library in the system environment, 
cmake will automatically help you download and compile the required version (the library provided by the system may lack certain features).

Another dependency is [pcap](https://github.com/the-tcpdump-group/libpcap), which will be searched for in the system path by default, 
but you can also let cmake automatically compile pcap by using `-DUSE_SYSTEM_PCAP=OFF`.

```shell
# native build
cmake -B build
cmake --build build pppwn

# cross compile for mipsel linux
cmake -B build -DZIG_TARGET=mipsel-linux-musl -DUSE_SYSTEM_PCAP=OFF
cmake --build build pppwn

# cross compile for Windows
cmake -B build -DZIG_TARGET=x86_64-windows-gnu -DUSE_SYSTEM_PCAP=OFF -DPacket_ROOT=<path to npcap sdk>
cmake --build build pppwn
```

# progress
- [x] Stage 0
- [x] Stage 1
- [x] Stage 2
- [ ] Stage 3
- [ ] Stage 4

Big thanks to FloW's magical work, you are my hero.


