# PPPwn c++

This is the C++ rewrite of [PPPwn](https://github.com/TheOfficialFloW/PPPwn)

# Features

- Smaller binary size
- A wide range of CPU architectures and systems are supported
- Run faster under Windows (more accurate sleep time)
- Restart automatically when failing
- Can be compiled as a library integrated into your application

# Nightly build

You can download the latest build from [nightly.link](https://nightly.link/xfangfang/PPPwn_cpp/workflows/ci.yaml/main?status=completed).

For Windows users, you need to install [npcap](https://npcap.com) before run this program.
There are lots of GUI wrapper for pppwn_cpp, it's better to use them if you are not familiar with command line.

For macOS users, you need to run `sudo xattr -rd com.apple.quarantine <path-to-pppwn>` after download.
Please refer to [#10](https://github.com/xfangfang/PPPwn_cpp/issues/10) for more information.

# Usage

### show help

```shell
pppwn
```

### list interfaces

```shell
pppwn list
```

### run the exploit

```shell
pppwn --interface en0 --fw 1100 --stage1 "stage1.bin" --stage2 "stage2.bin" --timeout 10 --auto-retry
```

- `-i` `--interface`: the network interface which connected to ps4
- `--fw`: the firmware version of the target ps4 (default: `1100`)
- `-s1` `--stage1`: the path to the stage1 payload (default: `stage1/stage1.bin`)
- `-s2` `--stage2`: the path to the stage2 payload (default: `stage2/stage2.bin`)
- `-t` `--timeout`: the timeout in seconds for ps4 response, 0 means always wait (default: `0`)
- `-a` `--auto-retry`: automatically retry when fails or timeout
- `-nw` `--no-wait-padi`: don't wait one more [PADI](https://en.wikipedia.org/wiki/Point-to-Point_Protocol_over_Ethernet#Client_to_server:_Initiation_(PADI)) before starting the exploit

Supplement:

1. For `--timeout`, `PADI` is not included, which allows you to start `pppwn_cpp` before the ps4 is launched.
2. For `--no-wait-padi`, by default, `pppwn_cpp` will wait for two `PADI` request, according to [PPPwn/pull/48](https://github.com/TheOfficialFloW/PPPwn/pull/48) this helps to improve stability. You can turn off this feature with this parameter if you don't need it.


# Development

This project depends on [pcap](https://github.com/the-tcpdump-group/libpcap), cmake will search for it in the system path by default.
You can also add cmake option `-DUSE_SYSTEM_PCAP=OFF` to compile pcap from source (can be used when cross-compiling).

Please refer to the workflow file [.github/workflows/ci.yaml](.github/workflows/ci.yaml) for more information.

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


