#!/usr/bin/env node

// ============================================================
// hash-it - Hash passwords, generate checksums, verify hashes
// ONE dependency: bcryptjs
// ============================================================

import * as crypto from "crypto";
import * as fs from "fs";
import * as readline from "readline";
import bcrypt from "bcryptjs";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";

function printHelp(): void {
  console.log(`
${BOLD}${CYAN}hash-it${RESET} - Hash passwords, generate checksums, verify hashes

${BOLD}USAGE${RESET}
  hash-it ${DIM}<command> [options]${RESET}

${BOLD}COMMANDS${RESET}
  password ${DIM}<text>${RESET}           Hash a password with bcrypt
  verify ${DIM}<text> <hash>${RESET}      Verify a password against a bcrypt hash
  checksum ${DIM}<file>${RESET}           Generate file checksum
  text ${DIM}<string>${RESET}             Hash a text string

${BOLD}OPTIONS${RESET}
  --help, -h             Show this help message
  --json                 Output as JSON
  --algo, -a <algo>      Hash algorithm: sha256, sha512, md5 (default: sha256)
  --rounds, -r <N>       Bcrypt rounds (default: 10)
  --encoding, -e <enc>   Output encoding: hex, base64 (default: hex)

${BOLD}EXAMPLES${RESET}
  ${DIM}# Hash a password${RESET}
  hash-it password "my-secret-password"

  ${DIM}# Verify a password${RESET}
  hash-it verify "my-secret" "$2a$10$..."

  ${DIM}# File checksum (SHA-256)${RESET}
  hash-it checksum package.json

  ${DIM}# File checksum (MD5)${RESET}
  hash-it checksum --algo md5 large-file.zip

  ${DIM}# Hash text with SHA-512${RESET}
  hash-it text --algo sha512 "hello world"

  ${DIM}# JSON output${RESET}
  hash-it --json checksum myfile.txt
`);
}

function hashText(
  text: string,
  algo: string,
  encoding: "hex" | "base64"
): string {
  return crypto.createHash(algo).update(text).digest(encoding);
}

async function hashFile(
  filePath: string,
  algo: string,
  encoding: "hex" | "base64"
): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(algo);
    const stream = fs.createReadStream(filePath);
    stream.on("data", (data) => hash.update(data));
    stream.on("end", () => resolve(hash.digest(encoding)));
    stream.on("error", reject);
  });
}

function hashPassword(password: string, rounds: number): string {
  const salt = bcrypt.genSaltSync(rounds);
  return bcrypt.hashSync(password, salt);
}

function verifyPassword(password: string, hash: string): boolean {
  return bcrypt.compareSync(password, hash);
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  const jsonOutput = args.includes("--json");

  // Parse options
  let algo = "sha256";
  let rounds = 10;
  let encoding: "hex" | "base64" = "hex";

  const algoIdx =
    args.indexOf("--algo") !== -1
      ? args.indexOf("--algo")
      : args.indexOf("-a");
  if (algoIdx !== -1 && args[algoIdx + 1]) {
    algo = args[algoIdx + 1].toLowerCase();
  }

  const roundsIdx =
    args.indexOf("--rounds") !== -1
      ? args.indexOf("--rounds")
      : args.indexOf("-r");
  if (roundsIdx !== -1 && args[roundsIdx + 1]) {
    rounds = parseInt(args[roundsIdx + 1], 10);
  }

  const encIdx =
    args.indexOf("--encoding") !== -1
      ? args.indexOf("--encoding")
      : args.indexOf("-e");
  if (encIdx !== -1 && args[encIdx + 1]) {
    encoding = args[encIdx + 1].toLowerCase() as "hex" | "base64";
  }

  // Get command and positional args
  const flags = new Set([
    "--json", "--help", "-h",
    "--algo", "-a", "--rounds", "-r", "--encoding", "-e",
  ]);
  const flagsWithValues = new Set(["--algo", "-a", "--rounds", "-r", "--encoding", "-e"]);
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (flags.has(args[i])) {
      if (flagsWithValues.has(args[i])) i++;
      continue;
    }
    positional.push(args[i]);
  }

  const command = positional[0];

  if (!command) {
    console.error(`${RED}Error:${RESET} No command provided. Run ${CYAN}hash-it --help${RESET} for usage.`);
    process.exit(1);
  }

  switch (command) {
    case "password": {
      const text = positional.slice(1).join(" ");
      if (!text) {
        console.error(`${RED}Error:${RESET} Please provide a password to hash.`);
        process.exit(1);
      }
      const start = Date.now();
      const hash = hashPassword(text, rounds);
      const elapsed = Date.now() - start;

      if (jsonOutput) {
        console.log(
          JSON.stringify({
            command: "password",
            algorithm: "bcrypt",
            rounds,
            hash,
            timeMs: elapsed,
          }, null, 2)
        );
      } else {
        console.log(`\n${BOLD}${CYAN}  Bcrypt Hash${RESET}`);
        console.log(`  ${DIM}Algorithm:${RESET} bcrypt (${rounds} rounds)`);
        console.log(`  ${DIM}Time:${RESET}      ${elapsed}ms`);
        console.log(`  ${BOLD}${GREEN}Hash:${RESET}      ${hash}\n`);
      }
      break;
    }

    case "verify": {
      const password = positional[1];
      const hash = positional[2];
      if (!password || !hash) {
        console.error(
          `${RED}Error:${RESET} Usage: hash-it verify <password> <hash>`
        );
        process.exit(1);
      }
      const match = verifyPassword(password, hash);

      if (jsonOutput) {
        console.log(
          JSON.stringify({ command: "verify", match }, null, 2)
        );
      } else {
        if (match) {
          console.log(`\n  ${GREEN}${BOLD}  MATCH${RESET} Password matches the hash.\n`);
        } else {
          console.log(`\n  ${RED}${BOLD}  NO MATCH${RESET} Password doesn't match the hash.\n`);
        }
      }
      process.exit(match ? 0 : 1);
      break;
    }

    case "checksum": {
      const filePath = positional[1];
      if (!filePath) {
        console.error(`${RED}Error:${RESET} Please provide a file path.`);
        process.exit(1);
      }
      if (!fs.existsSync(filePath)) {
        console.error(`${RED}Error:${RESET} File not found: ${filePath}`);
        process.exit(1);
      }

      const stat = fs.statSync(filePath);
      const start = Date.now();
      const hash = await hashFile(filePath, algo, encoding);
      const elapsed = Date.now() - start;

      if (jsonOutput) {
        console.log(
          JSON.stringify({
            command: "checksum",
            file: filePath,
            size: stat.size,
            algorithm: algo,
            encoding,
            hash,
            timeMs: elapsed,
          }, null, 2)
        );
      } else {
        console.log(`\n${BOLD}${CYAN}  File Checksum${RESET}`);
        console.log(`  ${DIM}File:${RESET}      ${filePath}`);
        console.log(`  ${DIM}Size:${RESET}      ${formatFileSize(stat.size)}`);
        console.log(`  ${DIM}Algorithm:${RESET} ${algo.toUpperCase()}`);
        console.log(`  ${DIM}Encoding:${RESET}  ${encoding}`);
        console.log(`  ${DIM}Time:${RESET}      ${elapsed}ms`);
        console.log(`  ${BOLD}${GREEN}Hash:${RESET}      ${hash}\n`);
      }
      break;
    }

    case "text": {
      const text = positional.slice(1).join(" ");
      if (!text) {
        console.error(`${RED}Error:${RESET} Please provide text to hash.`);
        process.exit(1);
      }
      const hash = hashText(text, algo, encoding);

      if (jsonOutput) {
        console.log(
          JSON.stringify({
            command: "text",
            input: text,
            algorithm: algo,
            encoding,
            hash,
          }, null, 2)
        );
      } else {
        console.log(`\n${BOLD}${CYAN}  Text Hash${RESET}`);
        console.log(`  ${DIM}Input:${RESET}     "${text}"`);
        console.log(`  ${DIM}Algorithm:${RESET} ${algo.toUpperCase()}`);
        console.log(`  ${DIM}Encoding:${RESET}  ${encoding}`);
        console.log(`  ${BOLD}${GREEN}Hash:${RESET}      ${hash}\n`);
      }
      break;
    }

    default:
      console.error(
        `${RED}Error:${RESET} Unknown command "${command}". Run ${CYAN}hash-it --help${RESET} for usage.`
      );
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(`${RED}Error:${RESET} ${err.message}`);
  process.exit(1);
});
