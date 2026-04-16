# Crypto Wizard

An interactive, wizard-style CLI tool for encrypting and decrypting data using six classical and modern cryptographic algorithms. Every parameter — plaintext, keys, IVs — is entered at runtime. Nothing is hardcoded.

---

## Algorithms

| # | Algorithm | Type | Key Size | Implementation |
|---|-----------|------|----------|----------------|
| 1 | **Caesar Cipher** | Classical substitution | Shift 1–25 | Pure Python |
| 2 | **RC4** | Stream cipher | 128-bit (16 bytes) | Pure Python |
| 3 | **DES-CBC** | Block cipher | 56-bit (8 bytes) | OpenSSL |
| 4 | **Triple DES (3DES-CBC)** | Block cipher | 168-bit (24 bytes) | OpenSSL |
| 5 | **IDEA** | Block cipher | 128-bit (16 bytes) | Pure Python |
| 6 | **AES-256-CBC** | Block cipher | 256-bit (32 bytes) | OpenSSL |

---

## Features

- **Wizard interface** — step-by-step prompts guide you through every parameter
- **Dynamic input** — type plaintext inline or point to any file on disk
- **Key & IV generation** — generate cryptographically secure random keys/IVs with one keypress, or paste your own hex values
- **Three operation modes** — *encrypt only*, *decrypt only*, or *both* (encrypt then verify by decrypting back)
- **Full output** — complete hex, Base64, and plaintext results with no truncation
- **Run All** — execute every algorithm back-to-back, each with its own inputs
- **Rich UI** — colour-coded panels and tables (degrades gracefully to plain text if `rich` is not installed)
- **Auto-detects OpenSSL** — finds `openssl.exe` and the legacy provider (`legacy.dll`) automatically, even if they are not on `PATH`

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.9 or later |
| [rich](https://github.com/Textualize/rich) | 13.0 or later |
| OpenSSL | 3.x (full installer — **not** the Light version) |

> DES and 3DES require the OpenSSL **legacy provider** (`legacy.dll`). The full installer from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html) includes it. The "Light" version does not.

---

## Installation

### 1. Clone or download

```bash
git clone https://github.com/ahmed-hesham07/crypto-ops.git
cd crypto-ops
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Install OpenSSL (Windows)

Download and run the **Win64 OpenSSL v3.x.x** full installer (not Light):  
https://slproweb.com/products/Win32OpenSSL.html

Then add the `bin` directory to your PATH:

```powershell
# Run once in PowerShell (no admin required)
[System.Environment]::SetEnvironmentVariable(
    "Path",
    [System.Environment]::GetEnvironmentVariable("Path","User") + ";C:\Program Files\OpenSSL-Win64\bin",
    "User"
)
```

Open a new terminal and verify:

```powershell
openssl version
# OpenSSL 3.x.x ...
```

---

## Usage

```bash
python crypto_wizard.py
```

You will be greeted by the main menu:

```
╔══════════════════════════════════════════════════════════╗
║                     CRYPTO WIZARD                        ║
║      Classical & Modern Cryptographic Algorithms         ║
║  Caesar · RC4 · DES · 3DES · IDEA · AES-256              ║
╚══════════════════════════════════════════════════════════╝

        Choose an Algorithm
  ┌─────┬────────────────────────┬──────────────────────────────────┐
  │  1  │ Caesar Cipher          │ Part 1  — Classical substitution │
  │  2  │ RC4 Stream Cipher      │ Part 2  — Stream cipher          │
  │  3  │ DES-CBC                │ Part 3A — 56-bit block cipher    │
  │  4  │ Triple DES (3DES-CBC)  │ Part 3B — 168-bit block cipher   │
  │  5  │ IDEA                   │ Part 3B — 128-bit block cipher   │
  │  6  │ AES-256-CBC            │ Part 3B — 256-bit block cipher   │
  │  A  │ Run ALL algorithms     │ Run every algorithm sequentially │
  │  0  │ Exit                   │                                  │
  └─────┴────────────────────────┴──────────────────────────────────┘
```

### Wizard walkthrough (example: AES-256)

```
Step 1/4  Operation Mode
  Choose operation: both (encrypt → verify decrypt)

Step 2/4  Input Data
  Input source [text/file]: text
  Enter plaintext: API 579 Fitness for Service Assessment

Step 3/4  AES-256-CBC Key  (256-bit)
  Generate random 32-byte key? [y/n]: y
  Generated: 3A9F2C... (64 hex chars)

Step 4/4  Initialization Vector — IV  (128-bit)
  Generate random 16-byte IV? [y/n]: y
  Generated: 1B3D5E... (32 hex chars)

┌─ AES-256-CBC — Results ────────────────────────────────────────┐
│ Input            API 579 Fitness for Service Assessment        │
│ Input size       38 bytes                                      │
│ Key (hex)        3A9F2C...                                     │
│ IV (hex)         1B3D5E...                                     │
│ Encrypted (hex)  4F8A1C...                                     │
│ Encrypted (b64)  T4oc...==                                     │
│ Encrypted size   48 bytes                                      │
│ Decrypted        API 579 Fitness for Service Assessment        │
│ Verify Match     YES ✓                                         │
└────────────────────────────────────────────────────────────────┘
```

### File encryption

When prompted for input source, choose `file` and enter the path:

```
Input source [text/file]: file
File path: C:\Documents\report.pdf
Loaded 204800 bytes from C:\Documents\report.pdf
```

The entire file is encrypted in memory; the result is printed as hex and Base64.

### Decrypt-only mode

Choose `decrypt only` at the operation step. The wizard will ask for the ciphertext as a hex string, then the key (and IV if applicable), and return the plaintext.

---

## Project Structure

```
crypto-ops/
├── crypto_wizard.py   # Main application — all crypto logic and CLI wizard
└── requirements.txt   # Python dependencies (rich)
```

---

## Algorithm Notes

### Caesar Cipher
Shifts each letter in the alphabet by a fixed amount. Non-alphabetic characters are passed through unchanged. Decryption is encryption with the negative shift.

### RC4
A symmetric stream cipher implemented from scratch using the Key Scheduling Algorithm (KSA) and Pseudo-Random Generation Algorithm (PRGA). Because RC4 is symmetric, encryption and decryption are the same operation.

### DES-CBC
Data Encryption Standard in Cipher Block Chaining mode. Requires an 8-byte (64-bit) key and an 8-byte IV. Delegates to OpenSSL with the legacy provider enabled.

### Triple DES (3DES-CBC)
Applies DES three times with a 24-byte (192-bit) key for significantly stronger security than single DES. Delegates to OpenSSL with the legacy provider enabled.

### IDEA
International Data Encryption Algorithm. Operates on 64-bit blocks with a 128-bit key over 8 rounds using multiplication mod 2¹⁶+1 and addition mod 2¹⁶. Implemented entirely in Python with ECB mode and PKCS7 padding.

### AES-256-CBC
Advanced Encryption Standard with a 256-bit key in Cipher Block Chaining mode. The current industry standard for symmetric encryption. Delegates to OpenSSL.

---

## License

This project is released for educational purposes.
