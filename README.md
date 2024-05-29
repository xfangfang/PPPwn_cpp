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
- `-wap` `--wait-after-pin`: the waiting time in seconds after first round CPU pinning (default: `1`)
- `-gd` `--groom-delay`: wait for 1ms every `groom-delay` rounds during Heap grooming (default: `4`)
- `-bs` `--buffer-size`: PCAP buffer size in bytes, less than 100 indicates default value (usually 2MB) (default: `0`)
- `-a` `--auto-retry`: automatically retry when fails or timeout
- `-nw` `--no-wait-padi`: don't wait one more [PADI](https://en.wikipedia.org/wiki/Point-to-Point_Protocol_over_Ethernet#Client_to_server:_Initiation_(PADI)) before starting the exploit
- `-rs` `--real-sleep`: use CPU for more precise sleep time (Only used when execution speed is too slow)
- `--web`: use the web interface
- `--url`: the url of the web interface (default: `0.0.0.0:7796`)

Supplement:

1. For `--timeout`, waiting for `PADI` is not included, which allows you to start `pppwn_cpp` before the ps4 is launched.
2. For `--no-wait-padi`, by default, `pppwn_cpp` will wait for two `PADI` request, according to [TheOfficialFloW/PPPwn/pull/48](https://github.com/TheOfficialFloW/PPPwn/pull/48) this helps to improve stability. You can turn off this feature with this parameter if you don't need it.
3. For `--wait-after-pin`, according to [SiSTR0/PPPwn/pull/1](https://github.com/SiSTR0/PPPwn/pull/1) set this parameter to `20` helps to improve stability (not work for me), this option not used in web interface.
4. For `--groom-delay`, This is an empirical value. The Python version of pppwn does not set any wait at Heap grooming, but if the C++ version does not add some wait, there is a probability of kernel panic on my ps4. You can set any value within 1-4097 (4097 is equivalent to not doing any wait).
5. For `--buffer-size`, When running on low-end devices, this value can be set to reduce memory usage. I tested that setting it to 10240 can run normally, and the memory usage is about 3MB. (Note: A value that is too small may cause some packets to not be captured properly)

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


