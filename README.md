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

For macOS users, you need to run `sudo xattr -rd com.apple.quarantine <path-to-pppwn>` after download, and install [chmodbpf](https://formulae.brew.sh/cask/wireshark-chmodbpf) before run this program.
Please refer to [#10](https://github.com/xfangfang/PPPwn_cpp/issues/10) for more information.

```shell
# show help
pppwn

# list interfaces
pppwn list

# run the exploit
pppwn --interface en0 --fw 1100 --stage1 "stage1.bin" --stage2 "stage2.bin" --auto-retry
```

# Development

This project depends on [pcap](https://github.com/the-tcpdump-group/libpcap), cmake will search for it in the system path by default.
You can also add cmake option `-DUSE_SYSTEM_PCAP=OFF` to compile pcap from source (can be used when cross-compiling).

```shell
# native build (macOS, Linux)
cmake -B build
cmake --build build -t pppwn

# cross compile for mipsel linux (soft float)
cmake -B build -DZIG_TARGET=mipsel-linux-musl -DUSE_SYSTEM_PCAP=OFF -DZIG_COMPILE_OPTION="-msoft-float"
cmake --build build -t pppwn

# cross compile for arm linux (armv7 cortex-a7)
cmake -B build -DZIG_TARGET=arm-linux-musleabi -DUSE_SYSTEM_PCAP=OFF -DZIG_COMPILE_OPTION="-mcpu=cortex_a7"
cmake --build build -t pppwn

# cross compile for Windows
# https://npcap.com/dist/npcap-sdk-1.13.zip
cmake -B build -DZIG_TARGET=x86_64-windows-gnu -DUSE_SYSTEM_PCAP=OFF -DPacket_ROOT=<path to npcap sdk>
cmake --build build -t pppwn
```

# Credits

Big thanks to FloW's magical work, you are my hero.


