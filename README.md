# PPPwn c++ [WIP]

This is the C++ rewrite of [PPPwn](https://github.com/TheOfficialFloW/PPPwn), intended to run on small devices such as routers.

> [!CAUTION]
>
> This project is still work in progress and is currently not suitable for daily use.

To avoid mistakes, I wrote some test code to ensure that the packet sent by the c++ version 
is the same as the packet sent by the python version, these tests are in the `tests` directory.

But in actual operation, the failure rate of the c++ version is very high (stopping at stage1),
I think this may be due to the different execution speeds of c++ and python.

Welcome any developers who are interested to improve this project together.

# Nightly build

You can download the latest build from [nightly.link](https://nightly.link/xfangfang/PPPwn_cpp/workflows/ci.yaml/main?status=completed).

For Windows users, you need to install [npcap](https://npcap.com) before run this program.

```shell
pppwn --interface en6 --fw 1100 --stage1 <stage1.bin> stage2 <stage2.bin>
```

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

# Progress

- [x] Stage 0
- [x] Stage 1
- [x] Stage 2
- [x] Stage 3
- [x] Stage 4

Big thanks to FloW's magical work, you are my hero.


