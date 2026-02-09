# hash-it

[![npm version](https://img.shields.io/npm/v/@lxgicstudios/hash-it.svg)](https://www.npmjs.com/package/@lxgicstudios/hash-it)
[![license](https://img.shields.io/npm/l/@lxgicstudios/hash-it.svg)](https://github.com/lxgicstudios/hash-it/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/@lxgicstudios/hash-it.svg)](https://nodejs.org)

Hash passwords with bcrypt, generate file checksums (SHA-256, SHA-512, MD5), and verify hashes. All from the command line. One dependency (bcryptjs).

## Install

```bash
npm install -g @lxgicstudios/hash-it
```

Or run directly:

```bash
npx @lxgicstudios/hash-it password "my-secret"
```

## Features

- Hash passwords with bcrypt (configurable rounds)
- Verify passwords against bcrypt hashes
- Generate file checksums (SHA-256, SHA-512, MD5)
- Hash arbitrary text strings
- Multiple output encodings (hex, base64)
- JSON output for scripting
- Colorful terminal output
- Just one external dependency (bcryptjs)

## Usage

### Hash a password

```bash
hash-it password "my-secret-password"
# => $2a$10$K8Y1...
```

### Verify a password

```bash
hash-it verify "my-secret" '$2a$10$K8Y1...'
# => MATCH or NO MATCH
```

### File checksum

```bash
hash-it checksum package.json
# => SHA-256: a1b2c3d4...

hash-it checksum --algo md5 large-file.zip
# => MD5: e5f6a7b8...
```

### Hash text

```bash
hash-it text "hello world"
# => SHA-256: b94d27b9...

hash-it text --algo sha512 "hello world"
```

## Options

| Option | Alias | Default | Description |
|--------|-------|---------|-------------|
| `--help` | `-h` | | Show help message |
| `--json` | | | Output as JSON |
| `--algo` | `-a` | `sha256` | Hash algorithm: sha256, sha512, md5 |
| `--rounds` | `-r` | `10` | Bcrypt salt rounds |
| `--encoding` | `-e` | `hex` | Output encoding: hex, base64 |

## Commands

| Command | Description |
|---------|-------------|
| `password <text>` | Hash a password with bcrypt |
| `verify <text> <hash>` | Verify password against bcrypt hash |
| `checksum <file>` | Generate file checksum |
| `text <string>` | Hash a text string |

## License

MIT - [LXGIC Studios](https://lxgicstudios.com)
