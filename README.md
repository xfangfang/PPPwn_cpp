# PPPwn c++

This is the C++ rewrite of [PPPwn](https://github.com/TheOfficialFloW/PPPwn)

# Features

- Smaller binary size
- A wide range of CPU architectures and systems are supported
- Run faster under Windows (more accurate sleep time)
- Restart automatically when failing at stage1
- Can be compiled as a library integrated into your application

# Nightly build

You can download the latest build from [nightly.link](https://nightly.link/xfangfang/PPPwn_cpp/workflows/ci.yaml/main?status=completed).

For Windows users, you need to install [npcap](https://npcap.com) before run this program.

```shell
# show help
pppwn

# list interfaces
pppwn list

# run the exploit
pppwn --interface en0 --fw 1100 --stage1 <stage1.bin> --stage2 <stage2.bin> --auto-retry
```

# Development

The project depends on [pcap++](https://github.com/seladb/PcapPlusPlus), but you don't need to install this library in the system environment, 
cmake will automatically help you download and compile the required version (the library provided by the package manager may lack certain features).

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


