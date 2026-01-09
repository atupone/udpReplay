# udpReplay

`udpReplay` is a high-performance C utility designed to replay network traffic from PCAP files as UDP datagrams. It is specifically optimized for replaying surveillance data, featuring specialized support for the **ASTERIX** protocol.

## Features

* **Hybrid Spin-Wait Timing**: Combines `clock_nanosleep` with high-precision CPU busy-waiting for the final 200 microseconds to eliminate OS scheduling jitter.
* **Kernel Batch Sending**: Utilizes the Linux-specific `sendmmsg()` system call to send multiple UDP datagrams in a single context switch for high-throughput replays.
* **ASTERIX Support**: Automatically adjusts "Time of Day" (ToD) fields within ASTERIX packets to reflect the actual wall-clock time of transmission.
* **Robust Header Parsing**: Implements strict boundary and validation checks for Ethernet, VLAN, and IPv4 headers (including IP Options).

## Installation

### Prerequisites
* `libpcap` development headers.
* Linux Kernel 3.0+ (required for `sendmmsg` support).
* Standard GNU Build System (Autoconf, Automake).

### Building from Source
This project uses the GNU Autotools. To compile and install `udpReplay`, run:

```bash
./configure
make
sudo make install
```

*Note: The `configure` script automatically handles the `_GNU_SOURCE` definition and required library linking (`-lpcap`, `-lrt`).*

## Usage

```bash
udpreplay [-options..] pcap-file
```

### Options
| Option | Description |
| :--- | :--- |
| `--astx` | Adjust Asterix Time Of Day to reflect actual send time. |
| `-b`, `--broadcast` | Enable sending of broadcast datagrams. |
| `-d`, `--dest <host>` | Redirect all replayed traffic to a specific destination host. |
| `-p`, `--port <port>` | Redirect all replayed traffic to a specific UDP port. |
| `-f`, `--flood [usec]` | Send packets in batches. The `usec` delay is applied **per batch**. |
| `-1`, `--onebyone` | Wait for `<Enter>` key between sending each packet. |
| `-l`, `--loop [usec]` | Loop the PCAP indefinitely with a delay between cycles. |

## Technical Notes

* **Safety**: The tool strictly validates packet lengths. Truncated packets are discarded to maintain data integrity.
* **Memory Integrity**: Asterix modifications are performed on a local buffer copy, preserving the original PCAP data in memory for consistent loops.
* **Resource Management**: Sockets are properly closed and recreated between replay cycles to prevent file descriptor leaks.

## License

Copyright (c) 2016 Tupone Alfredo.
This project is released under the terms of the GNU General Public License.
