# NullSec SSHBrute

> **SSH Authentication Tester**

[![Nim](https://img.shields.io/badge/nim-2.0+-yellow.svg)](https://nim-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da.svg)](https://discord.gg/killers)

SSH credential testing tool written in Nim with async concurrency.

## Build

```bash
nim c -d:release sshbrute.nim
```

## Usage

```bash
./sshbrute -t 192.168.1.1
./sshbrute -t target.com -U users.txt -P passwords.txt
./sshbrute -t 10.0.0.1 -u root -P rockyou.txt -c 20
```

## Features

- Async/await concurrency
- Built-in default credential lists
- Custom wordlist support
- Configurable timeout and delay
- JSON output mode

## Community

- **Discord**: [discord.gg/killers](https://discord.gg/killers)
- **GitHub**: [bad-antics](https://github.com/bad-antics)
