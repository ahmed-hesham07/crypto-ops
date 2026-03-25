#!/usr/bin/env python3
"""
Crypto CLI Wizard
Interactive step-by-step wizard for classical and modern cryptographic algorithms.
Supports: Caesar, RC4, DES, 3DES, IDEA, AES-256
"""

import os
import sys
import subprocess
import binascii
import tempfile
import secrets
from pathlib import Path

# ── Rich (pretty terminal output) ────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.rule import Rule
    from rich.align import Align
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

# ═══════════════════════════════════════════════════════════════════════════════
#  DISPLAY / INPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def cprint(msg, style=""):
    if HAS_RICH:
        console.print(msg, style=style)
    else:
        # Strip basic rich tags for plain output
        import re
        msg = re.sub(r'\[/?[^\]]+\]', '', msg)
        print(msg)


def ask(prompt, default=None, password=False):
    clean = _strip_tags(prompt)
    if HAS_RICH:
        return Prompt.ask(prompt, default=default, password=password)
    val = input(f"{clean}" + (f" [{default}]" if default else "") + ": ").strip()
    return val if val else (default or "")


def ask_int(prompt, default=None):
    clean = _strip_tags(prompt)
    if HAS_RICH:
        return IntPrompt.ask(prompt, default=default)
    while True:
        raw = input(f"{clean}" + (f" [{default}]" if default else "") + ": ").strip()
        if not raw and default is not None:
            return default
        try:
            return int(raw)
        except ValueError:
            print("  Please enter a valid integer.")


def confirm(prompt, default=True):
    clean = _strip_tags(prompt)
    if HAS_RICH:
        return Confirm.ask(prompt, default=default)
    hint = "Y/n" if default else "y/N"
    val = input(f"{clean} [{hint}]: ").strip().lower()
    return default if not val else val in ("y", "yes")


def ask_choice(prompt, choices, default=None):
    """Single-choice selection with numbered list."""
    clean = _strip_tags(prompt)
    if HAS_RICH:
        return Prompt.ask(prompt, choices=choices, default=default or choices[0])
    print(f"\n  {clean}:")
    for i, c in enumerate(choices, 1):
        print(f"    {i}. {c}")
    while True:
        raw = input(f"  Enter number (default: {default or choices[0]}): ").strip()
        if not raw and default:
            return default
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass
        print("  Invalid choice.")


def _strip_tags(text):
    import re
    return re.sub(r'\[/?[^\]]+\]', '', text)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def step_header(n, total, title):
    if HAS_RICH:
        console.print(f"\n[bold blue]  Step {n}/{total}[/bold blue]  [bold]{title}[/bold]")
    else:
        print(f"\n--- Step {n}/{total}: {title} ---")


def show_result(title, rows, match=None):
    """Display a result table inside a panel (or plain fallback)."""
    if HAS_RICH:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Field", style="bold cyan", min_width=22)
        table.add_column("Value", style="white", overflow="fold")
        for label, value in rows:
            table.add_row(label, str(value))
        if match is not None:
            icon = "[bold green]YES  ✓[/bold green]" if match else "[bold red]NO  ✗[/bold red]"
            table.add_row("Verify Match", icon)
        console.print()
        console.print(Panel(table, title=f"[bold green]{title}[/bold green]", border_style="green"))
    else:
        print(f"\n{'─' * 60}")
        print(f"  {title}")
        print(f"{'─' * 60}")
        for label, value in rows:
            print(f"  {label:<24}: {value}")
        if match is not None:
            print(f"  {'Verify Match':<24}: {'YES' if match else 'NO'}")
        print()


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMON WIZARD INPUT STEPS
# ═══════════════════════════════════════════════════════════════════════════════

def get_input_data(step_n, total_steps):
    """Step: choose text input or file, return (bytes, display_label)."""
    step_header(step_n, total_steps, "Input Data")
    source = ask_choice(
        "  Input source",
        choices=["text", "file"],
        default="text",
    )
    if source == "file":
        path = ask("  File path").strip().strip('"')
        try:
            data = Path(path).read_bytes()
            cprint(f"  [green]Loaded {len(data)} bytes from {path}[/green]")
            return data, f"{path}  ({len(data)} bytes)"
        except Exception as exc:
            cprint(f"  [red]Cannot read file: {exc}[/red]")
            sys.exit(1)
    else:
        text = ask("  Enter plaintext")
        return text.encode("utf-8"), text


def get_ciphertext_bytes(step_n, total_steps):
    """Step: enter hex ciphertext for decrypt-only mode."""
    step_header(step_n, total_steps, "Ciphertext Input (hex)")
    raw = ask("  Paste ciphertext hex").strip().replace(" ", "")
    try:
        return bytes.fromhex(raw)
    except ValueError:
        cprint("[red]  Invalid hex string.[/red]")
        sys.exit(1)


def get_hex_key(label, byte_len, step_n, total_steps):
    """Step: generate or enter a hex key. Returns bytes."""
    bits = byte_len * 8
    step_header(step_n, total_steps, f"{label}  ({bits}-bit)")
    gen = confirm(f"  Generate random {byte_len}-byte key?", default=True)
    if gen:
        key = secrets.token_bytes(byte_len)
        cprint(f"  [yellow]Generated:[/yellow] [bold]{key.hex().upper()}[/bold]")
        return key
    expected = byte_len * 2
    while True:
        raw = ask(f"  Enter key ({expected} hex chars)").strip().replace(" ", "").upper()
        if len(raw) != expected:
            cprint(f"  [red]Need {expected} hex chars, got {len(raw)}.[/red]")
            continue
        try:
            return bytes.fromhex(raw)
        except ValueError:
            cprint("  [red]Invalid hex string.[/red]")


def get_hex_iv(byte_len, step_n, total_steps):
    """Step: generate or enter an IV. Returns bytes."""
    bits = byte_len * 8
    step_header(step_n, total_steps, f"Initialization Vector — IV  ({bits}-bit)")
    gen = confirm(f"  Generate random {byte_len}-byte IV?", default=True)
    if gen:
        iv = secrets.token_bytes(byte_len)
        cprint(f"  [yellow]Generated:[/yellow] [bold]{iv.hex().upper()}[/bold]")
        return iv
    expected = byte_len * 2
    while True:
        raw = ask(f"  Enter IV ({expected} hex chars)").strip().replace(" ", "").upper()
        if len(raw) != expected:
            cprint(f"  [red]Need {expected} hex chars, got {len(raw)}.[/red]")
            continue
        try:
            return bytes.fromhex(raw)
        except ValueError:
            cprint("  [red]Invalid hex string.[/red]")


def get_operation(step_n, total_steps):
    """Step: choose encrypt / decrypt / both."""
    step_header(step_n, total_steps, "Operation Mode")
    return ask_choice(
        "  Choose operation",
        choices=["both (encrypt → verify decrypt)", "encrypt only", "decrypt only"],
        default="both (encrypt → verify decrypt)",
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 1: CAESAR CIPHER
# ═══════════════════════════════════════════════════════════════════════════════

def _caesar_shift(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def caesar_encrypt(text, shift):
    return _caesar_shift(text, shift)


def caesar_decrypt(text, shift):
    return _caesar_shift(text, -shift)


def wizard_caesar(standalone=True):
    if HAS_RICH:
        console.rule("[bold cyan]Caesar Cipher[/bold cyan]")
    else:
        print("\n" + "=" * 55 + "\n  CAESAR CIPHER\n" + "=" * 55)

    STEPS = 3

    # Step 1: input text
    step_header(1, STEPS, "Input Text")
    text = ask("  Enter text")

    # Step 2: shift value
    step_header(2, STEPS, "Shift Value")
    shift = ask_int("  Shift (1–25)", default=13)
    shift = max(1, min(25, abs(int(shift))))

    # Step 3: operation
    op = get_operation(3, STEPS)

    rows = [("Input Text", text), ("Shift", shift)]

    if "decrypt only" in op:
        dec = caesar_decrypt(text, shift)
        rows.append(("Decrypted", dec))
        show_result("Caesar — Decrypted", rows)
    elif "encrypt only" in op:
        enc = caesar_encrypt(text, shift)
        rows.append(("Encrypted", enc))
        show_result("Caesar — Encrypted", rows)
    else:  # both
        enc = caesar_encrypt(text, shift)
        dec = caesar_decrypt(enc, shift)
        rows += [("Encrypted", enc), ("Decrypted", dec)]
        show_result("Caesar — Results", rows, match=(dec == text))

    if standalone:
        return confirm("\n  Run another operation?", default=True)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 2: RC4 STREAM CIPHER
# ═══════════════════════════════════════════════════════════════════════════════

def _rc4_ksa(key_bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def _rc4_prga(S, length):
    i = j = 0
    ks = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        ks.append(S[(S[i] + S[j]) % 256])
    return ks


def rc4_crypt(data_bytes, key_bytes):
    S = _rc4_ksa(list(key_bytes))
    ks = _rc4_prga(S, len(data_bytes))
    return bytes([b ^ k for b, k in zip(data_bytes, ks)])


def wizard_rc4(standalone=True):
    if HAS_RICH:
        console.rule("[bold cyan]RC4 Stream Cipher[/bold cyan]")
    else:
        print("\n" + "=" * 55 + "\n  RC4 STREAM CIPHER\n" + "=" * 55)

    STEPS = 3

    op = get_operation(1, STEPS)

    if "decrypt only" in op:
        data = get_ciphertext_bytes(2, STEPS)
        label = f"<ciphertext> ({len(data)} bytes)"
    else:
        data, label = get_input_data(2, STEPS)

    key = get_hex_key("RC4 Key", 16, 3, STEPS)

    rows = [
        ("Input", str(label)),
        ("Key (hex)", key.hex().upper()),
    ]

    if "decrypt only" in op:
        dec = rc4_crypt(data, key)
        rows.append(("Decrypted", dec.decode("utf-8", errors="replace")))
        show_result("RC4 — Decrypted", rows)
    elif "encrypt only" in op:
        enc = rc4_crypt(data, key)
        rows += [
            ("Encrypted (hex)", enc.hex().upper()),
            ("Encrypted size", f"{len(enc)} bytes"),
        ]
        show_result("RC4 — Encrypted", rows)
    else:  # both
        enc = rc4_crypt(data, key)
        dec = rc4_crypt(enc, key)
        rows += [
            ("Encrypted (hex)", enc.hex().upper()),
            ("Encrypted size", f"{len(enc)} bytes"),
            ("Decrypted", dec.decode("utf-8", errors="replace")),
        ]
        show_result("RC4 — Results", rows, match=(dec == data))

    if standalone:
        return confirm("\n  Run another operation?", default=True)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  OPENSSL WRAPPER (DES / 3DES / AES-256)
# ═══════════════════════════════════════════════════════════════════════════════

_LEGACY_ALGOS = {"des-cbc", "des-ecb", "des-ede3-cbc", "des-ede3-ecb", "des3", "rc4"}


def _find_openssl_exe():
    """
    Return the full path to openssl.exe (or 'openssl' on Unix).
    Checks PATH first, then common Windows install locations.
    """
    import shutil
    found = shutil.which("openssl")
    if found:
        return found
    # Hard-coded fallback paths for Windows
    for candidate in [
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files\OpenSSL\bin\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
        r"C:\OpenSSL\bin\openssl.exe",
    ]:
        if Path(candidate).exists():
            return candidate
    return "openssl"  # last resort — let the OS raise FileNotFoundError


def _find_legacy_provider_path():
    """
    Locate the directory that contains legacy.dll (Windows) or legacy.so (Linux/macOS).
    Returns the directory path as a string, or None if not found.
    """
    import shutil
    dll_name = "legacy.dll" if os.name == "nt" else "legacy.so"
    candidates = []

    # Derive from wherever openssl.exe lives
    exe = shutil.which("openssl") or _find_openssl_exe()
    if exe and Path(exe).exists():
        exe_dir = Path(exe).resolve().parent
        install_root = exe_dir.parent
        candidates += [
            exe_dir,                                    # same dir as exe (common on Windows)
            install_root / "lib" / "ossl-modules",
            install_root / "lib64" / "ossl-modules",
            exe_dir / "ossl-modules",
        ]

    # Hard-coded Windows fallbacks
    for root in [
        r"C:\Program Files\OpenSSL-Win64",
        r"C:\Program Files\OpenSSL",
        r"C:\OpenSSL-Win64",
        r"C:\OpenSSL",
    ]:
        candidates += [
            Path(root) / "bin",
            Path(root) / "lib" / "ossl-modules",
        ]

    for d in candidates:
        if (d / dll_name).exists():
            return str(d)
    return None


def _openssl_run(algo, mode_flag, key_hex, iv_hex, data):
    """Run openssl enc. Returns ciphertext/plaintext bytes or raises."""
    in_fd, in_path = tempfile.mkstemp(suffix=".bin")
    out_fd, out_path = tempfile.mkstemp(suffix=".bin")
    try:
        os.write(in_fd, data)
        os.close(in_fd)
        os.close(out_fd)

        exe = _find_openssl_exe()
        cmd = [
            exe, "enc", f"-{algo}",
            mode_flag, "-nosalt",
            "-K", key_hex,
            "-in", in_path,
            "-out", out_path,
        ]

        if algo in _LEGACY_ALGOS:
            provider_dir = _find_legacy_provider_path()
            if provider_dir:
                cmd += ["-provider-path", provider_dir,
                        "-provider", "legacy", "-provider", "default"]
            else:
                # legacy.dll not found — raise a friendly error before calling openssl
                raise RuntimeError(
                    "legacy.dll not found.\n\n"
                    "The OpenSSL 'Light' installer does NOT include the legacy provider\n"
                    "needed for DES and 3DES.\n\n"
                    "Fix: install the FULL OpenSSL from https://slproweb.com/products/Win32OpenSSL.html\n"
                    "     (choose Win64 OpenSSL v3.x.x — NOT the 'Light' version)\n"
                    "Then re-open this terminal."
                )

        if iv_hex and "ecb" not in algo:
            cmd += ["-iv", iv_hex]

        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode().strip())

        with open(out_path, "rb") as f:
            return f.read()
    finally:
        for p in (in_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def _check_openssl():
    try:
        return subprocess.run([_find_openssl_exe(), "version"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def wizard_openssl(algo_name, algo_str, key_bytes, iv_bytes, standalone=True):
    """Generic wizard for any OpenSSL-backed cipher."""
    if HAS_RICH:
        console.rule(f"[bold cyan]{algo_name}[/bold cyan]")
    else:
        print(f"\n{'=' * 55}\n  {algo_name.upper()}\n{'=' * 55}")

    if not _check_openssl():
        cprint("[bold red]  OpenSSL not found in PATH. Please install OpenSSL and retry.[/bold red]")
        if standalone:
            return confirm("\n  Return to menu?", default=True)
        return True

    total_steps = 3 + (1 if iv_bytes > 0 else 0)

    op = get_operation(1, total_steps)

    if "decrypt only" in op:
        data = get_ciphertext_bytes(2, total_steps)
        label = f"<ciphertext> ({len(data)} bytes)"
    else:
        data, label = get_input_data(2, total_steps)

    key = get_hex_key(f"{algo_name} Key", key_bytes, 3, total_steps)

    iv = None
    if iv_bytes > 0:
        iv = get_hex_iv(iv_bytes, total_steps, total_steps)

    key_hex = key.hex().upper()
    iv_hex = iv.hex().upper() if iv else None

    rows = [
        ("Input", str(label)),
        ("Input size", f"{len(data)} bytes"),
        ("Key (hex)", key_hex),
    ]
    if iv_hex:
        rows.append(("IV (hex)", iv_hex))

    try:
        if "decrypt only" in op:
            dec = _openssl_run(algo_str, "-d", key_hex, iv_hex, data)
            dec_text = dec.decode("utf-8", errors="replace").rstrip("\x00\r\n")
            rows.append(("Decrypted", dec_text))
            show_result(f"{algo_name} — Decrypted", rows)

        elif "encrypt only" in op:
            enc = _openssl_run(algo_str, "-e", key_hex, iv_hex, data)
            rows += [
                ("Encrypted (hex)", enc.hex().upper()),
                ("Encrypted (b64)", binascii.b2a_base64(enc).decode().strip()),
                ("Encrypted size", f"{len(enc)} bytes"),
            ]
            show_result(f"{algo_name} — Encrypted", rows)

        else:  # both
            enc = _openssl_run(algo_str, "-e", key_hex, iv_hex, data)
            dec = _openssl_run(algo_str, "-d", key_hex, iv_hex, enc)
            dec_text = dec.decode("utf-8", errors="replace").rstrip("\x00")
            original = data.decode("utf-8", errors="replace")
            rows += [
                ("Encrypted (hex)", enc.hex().upper()),
                ("Encrypted (b64)", binascii.b2a_base64(enc).decode().strip()),
                ("Encrypted size", f"{len(enc)} bytes"),
                ("Decrypted", dec_text),
            ]
            show_result(f"{algo_name} — Results", rows, match=(dec_text.rstrip() == original.rstrip()))

    except RuntimeError as exc:
        cprint(f"\n  [bold red]OpenSSL error:[/bold red] {exc}")

    if standalone:
        return confirm("\n  Run another operation?", default=True)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 3B-ii: IDEA  (pure Python)
# ═══════════════════════════════════════════════════════════════════════════════

def _mul_mod(a, b):
    if a == 0:
        a = 0x10000
    if b == 0:
        b = 0x10000
    r = (a * b) % 0x10001
    return 0 if r == 0x10000 else r & 0xFFFF


def _add_mod(a, b):
    return (a + b) & 0xFFFF


def _mul_inv(x):
    if x == 0:
        return 0
    mod = 0x10001
    a, b = mod, x
    t0, t1 = 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        t0, t1 = t1, t0 - q * t1
    return (t0 % mod) & 0xFFFF


def _add_inv(x):
    return (0x10000 - x) & 0xFFFF


def _idea_expand_key(key_bytes):
    assert len(key_bytes) == 16
    key_bits = int.from_bytes(key_bytes, "big")
    subkeys = []
    for _ in range(7):
        for j in range(8):
            if len(subkeys) >= 52:
                break
            subkeys.append((key_bits >> (112 - 16 * j)) & 0xFFFF)
        key_bits = ((key_bits << 25) | (key_bits >> 103)) & ((1 << 128) - 1)
    return subkeys[:52]


def _idea_decrypt_subkeys(enc):
    dk = [0] * 52
    p = 0
    dk[p:p+4] = [_mul_inv(enc[48]), _add_inv(enc[49]), _add_inv(enc[50]), _mul_inv(enc[51])]
    dk[p+4], dk[p+5] = enc[46], enc[47]
    p += 6
    for r in range(7, 0, -1):
        base = r * 6
        dk[p:p+4] = [_mul_inv(enc[base]), _add_inv(enc[base+2]), _add_inv(enc[base+1]), _mul_inv(enc[base+3])]
        dk[p+4], dk[p+5] = enc[base-2], enc[base-1]
        p += 6
    dk[p:p+4] = [_mul_inv(enc[0]), _add_inv(enc[1]), _add_inv(enc[2]), _mul_inv(enc[3])]
    return dk


def _idea_block(block, sk):
    x1 = (block[0] << 8) | block[1]
    x2 = (block[2] << 8) | block[3]
    x3 = (block[4] << 8) | block[5]
    x4 = (block[6] << 8) | block[7]
    for r in range(8):
        k = sk[r * 6: r * 6 + 6]
        x1 = _mul_mod(x1, k[0])
        x2 = _add_mod(x2, k[1])
        x3 = _add_mod(x3, k[2])
        x4 = _mul_mod(x4, k[3])
        t1 = _mul_mod(x1 ^ x3, k[4])
        t2 = _mul_mod(_add_mod(x2 ^ x4, t1), k[5])
        t1 = _add_mod(t1, t2)
        x1 ^= t2
        x3 ^= t2
        x2 ^= t1
        x4 ^= t1
        if r < 7:
            x2, x3 = x3, x2
    y1 = _mul_mod(x1, sk[48])
    y2 = _add_mod(x2, sk[49])
    y3 = _add_mod(x3, sk[50])
    y4 = _mul_mod(x4, sk[51])
    return bytes([(y1 >> 8), y1 & 0xFF, (y2 >> 8), y2 & 0xFF,
                  (y3 >> 8), y3 & 0xFF, (y4 >> 8), y4 & 0xFF])


def _pkcs7_pad(data, bs):
    n = bs - len(data) % bs
    return data + bytes([n] * n)


def _pkcs7_unpad(data):
    return data[: -data[-1]]


def idea_encrypt(data, key):
    sk = _idea_expand_key(key)
    padded = _pkcs7_pad(data, 8)
    return b"".join(_idea_block(padded[i:i+8], sk) for i in range(0, len(padded), 8))


def idea_decrypt(data, key):
    sk = _idea_decrypt_subkeys(_idea_expand_key(key))
    plain = b"".join(_idea_block(data[i:i+8], sk) for i in range(0, len(data), 8))
    return _pkcs7_unpad(plain)


def wizard_idea(standalone=True):
    if HAS_RICH:
        console.rule("[bold cyan]IDEA Cipher[/bold cyan]")
    else:
        print(f"\n{'=' * 55}\n  IDEA CIPHER\n{'=' * 55}")

    STEPS = 3

    op = get_operation(1, STEPS)

    if "decrypt only" in op:
        data = get_ciphertext_bytes(2, STEPS)
        label = f"<ciphertext> ({len(data)} bytes)"
    else:
        data, label = get_input_data(2, STEPS)

    key = get_hex_key("IDEA Key", 16, 3, STEPS)

    rows = [
        ("Input", str(label)),
        ("Input size", f"{len(data)} bytes"),
        ("Key (hex)", key.hex().upper()),
        ("Mode", "ECB + PKCS7 padding"),
    ]

    try:
        if "decrypt only" in op:
            dec = idea_decrypt(data, key)
            rows.append(("Decrypted", dec.decode("utf-8", errors="replace")))
            show_result("IDEA — Decrypted", rows)

        elif "encrypt only" in op:
            enc = idea_encrypt(data, key)
            rows += [
                ("Encrypted (hex)", enc.hex().upper()),
                ("Encrypted size", f"{len(enc)} bytes"),
            ]
            show_result("IDEA — Encrypted", rows)

        else:  # both
            enc = idea_encrypt(data, key)
            dec = idea_decrypt(enc, key)
            rows += [
                ("Encrypted (hex)", enc.hex().upper()),
                ("Encrypted size", f"{len(enc)} bytes"),
                ("Decrypted", dec.decode("utf-8", errors="replace")),
            ]
            show_result("IDEA — Results", rows, match=(dec == data))

    except Exception as exc:
        cprint(f"\n  [bold red]IDEA error:[/bold red] {exc}")

    if standalone:
        return confirm("\n  Run another operation?", default=True)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  RUN ALL
# ═══════════════════════════════════════════════════════════════════════════════

_ALGO_MENU = [
    ("1", "Caesar Cipher",             None),
    ("2", "RC4 Stream Cipher",         None),
    ("3", "DES-CBC",                   ("des-cbc",     8,  8)),
    ("4", "Triple DES (3DES-CBC)",     ("des-ede3-cbc",24, 8)),
    ("5", "IDEA",                      None),
    ("6", "AES-256-CBC",               ("aes-256-cbc", 32,16)),
]


def wizard_run_all():
    if HAS_RICH:
        console.rule("[bold yellow]Run ALL Algorithms[/bold yellow]")
        cprint("[dim]  Each algorithm will prompt for its own inputs.[/dim]\n")
    else:
        print("\n===== RUN ALL =====\nEach algorithm will prompt for its own inputs.\n")

    for key, name, openssl_cfg in _ALGO_MENU:
        if HAS_RICH:
            console.print(f"\n[bold magenta]{'━' * 50}[/bold magenta]")
            console.print(f"[bold magenta]  {name}[/bold magenta]")
            console.print(f"[bold magenta]{'━' * 50}[/bold magenta]")
        else:
            print(f"\n{'─' * 50}\n  {name}\n{'─' * 50}")

        if key == "1":
            wizard_caesar(standalone=False)
        elif key == "2":
            wizard_rc4(standalone=False)
        elif key == "5":
            wizard_idea(standalone=False)
        else:
            algo_str, kb, ivb = openssl_cfg
            wizard_openssl(name, algo_str, kb, ivb, standalone=False)


# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER & MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    if HAS_RICH:
        console.print()
        console.print(Panel(
            Align.center(
                "[bold cyan]CRYPTO WIZARD[/bold cyan]\n"
                "[dim]Classical & Modern Cryptographic Algorithms[/dim]\n"
                "[dim]Caesar  ·  RC4  ·  DES  ·  3DES  ·  IDEA  ·  AES-256[/dim]"
            ),
            box=box.DOUBLE,
            border_style="cyan",
            padding=(1, 6),
        ))
    else:
        print("=" * 58)
        print("             CRYPTO WIZARD")
        print("   Classical & Modern Cryptographic Algorithms")
        print("   Caesar · RC4 · DES · 3DES · IDEA · AES-256")
        print("=" * 58)


_MENU_ROWS = [
    ("1", "Caesar Cipher",         "Part 1  — Classical substitution cipher"),
    ("2", "RC4 Stream Cipher",     "Part 2  — Symmetric stream cipher (pure Python)"),
    ("3", "DES-CBC",               "Part 3A — 56-bit block cipher (OpenSSL)"),
    ("4", "Triple DES (3DES-CBC)", "Part 3B — 168-bit block cipher (OpenSSL)"),
    ("5", "IDEA",                  "Part 3B — 128-bit block cipher (pure Python)"),
    ("6", "AES-256-CBC",           "Part 3B — 256-bit block cipher (OpenSSL)"),
    ("A", "Run ALL algorithms",    "Run every algorithm sequentially"),
    ("0", "Exit",                  ""),
]


def print_main_menu():
    if HAS_RICH:
        console.print()
        t = Table(
            title="[bold]Choose an Algorithm[/bold]",
            box=box.ROUNDED,
            border_style="bright_blue",
            header_style="bold magenta",
            padding=(0, 1),
            show_header=True,
        )
        t.add_column("#",           style="bold yellow",  width=3)
        t.add_column("Algorithm",   style="bold white",   min_width=24)
        t.add_column("Description", style="dim",          min_width=42)
        for key, name, desc in _MENU_ROWS:
            if key == "0":
                t.add_row("[red]0[/red]", "[red]Exit[/red]", "")
            elif key == "A":
                t.add_row("[green]A[/green]", f"[green]{name}[/green]", f"[dim]{desc}[/dim]")
            else:
                t.add_row(key, name, desc)
        console.print(t)
    else:
        print("\n  ┌─ Select an Algorithm ──────────────────────────────────┐")
        for key, name, desc in _MENU_ROWS:
            print(f"  │  [{key}]  {name:<26} {desc[:30]}")
        print("  └────────────────────────────────────────────────────────┘")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if not HAS_RICH:
        print("\nTip: run  pip install rich  for a prettier interface.\n")

    print_banner()

    while True:
        print_main_menu()

        if HAS_RICH:
            choice = Prompt.ask("\n[bold]  Your choice[/bold]", default="0").strip().upper()
        else:
            choice = input("\n  Your choice: ").strip().upper()

        if choice == "0":
            cprint("\n[bold cyan]  Goodbye! Stay encrypted.[/bold cyan]\n")
            break

        elif choice == "1":
            if not wizard_caesar():
                break

        elif choice == "2":
            if not wizard_rc4():
                break

        elif choice == "3":
            if not wizard_openssl("DES-CBC", "des-cbc", 8, 8):
                break

        elif choice == "4":
            if not wizard_openssl("Triple DES (3DES-CBC)", "des-ede3-cbc", 24, 8):
                break

        elif choice == "5":
            if not wizard_idea():
                break

        elif choice == "6":
            if not wizard_openssl("AES-256-CBC", "aes-256-cbc", 32, 16):
                break

        elif choice == "A":
            wizard_run_all()
            if not confirm("\n  Return to main menu?", default=True):
                break

        else:
            cprint("[red]  Invalid choice — please enter 0–6 or A.[/red]")


if __name__ == "__main__":
    main()
