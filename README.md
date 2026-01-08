# udpReplay

`udpReplay` is a high-performance C utility designed to replay network traffic from PCAP files as UDP datagrams. It is specifically optimized for replaying surveillance data, featuring specialized support for the **ASTERIX** protocol.

## Features

* **High-Resolution Timing**: Uses POSIX monotonic clocks and absolute nanosecond timers (`clock_nanosleep`) to ensure replay fidelity and eliminate timing drift.
* **ASTERIX Support**: Automatically adjusts "Time of Day" (ToD) fields within ASTERIX packets to reflect the actual wall-clock time of transmission.
* **Flexible Replay Modes**:
    * **Real-time**: Replays packets following the original PCAP timestamps.
    * **Flood**: Sends packets as fast as possible with a configurable microsecond delay.
    * **One-by-One**: Interactive mode allowing manual stepping through packets via the `<Enter>` key.
* **Network Options**: Supports broadcast transmission, custom destination redirection, and configurable Multicast TTL.
* **VLAN Awareness**: Capable of parsing and stripping IEEE 802.1Q VLAN tags from the source PCAP.

## Installation

### Prerequisites
* `libpcap` development headers.
* A C compiler (GCC recommended).
* Standard POSIX environment (Linux/Unix).

### Compilation
You can compile the project using the following command. Note that you must link the Real-time library (`-lrt`) for high-resolution timers and `libpcap` for packet processing.

```bash
gcc -o udpreplay \
    udpReplay.c \
    udpCallback.c \
    asterix.c \
    -lpcap -lrt
```

## Usage

```bash
udpreplay [-options..] pcap-file
```

### Options
| Option | Description |
| :--- | :--- |
| `--astx` | Adjust Asterix Time Of Day to reflect the actual send time. |
| `-b`, `--broadcast` | Enable sending of broadcast datagrams. |
| `-d`, `--dest <host>` | Redirect all replayed traffic to a specific destination host. |
| `-p`, `--port <port>` | Redirect all replayed traffic to a specific UDP port. |
| `-f`, `--flood <usec>` | Send packets with a fixed `<usec>` delay between them. |
| `-1`, `--onebyone` | Wait for `<Enter>` key between sending each packet. |
| `-l`, `--loop <usec>` | Loop the PCAP file indefinitely with a delay between cycles. |
| `-t`, `--ttl <value>` | Set the Multicast TTL value. |

## Project Structure

* `udpReplay.c`: Main entry point and CLI argument parsing.
* `udpCallback.c`: Core logic for packet processing, timing control, and transmission.
* `asterix.c`: Logic for identifying and modifying ASTERIX protocol fields (Category 34, 48, etc.).
* `atxDepack.c` / `blockDepack.c`: Specialized tools for unpacking and inspecting ASTERIX data blocks.

## License

Copyright (c) 2016 Tupone Alfredo. This project is released under the terms of the license found in the `COPYING` file.
