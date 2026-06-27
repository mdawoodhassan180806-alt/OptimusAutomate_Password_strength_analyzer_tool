# 🔐 Password Strength Analyzer

> **Task 1 — Kali Linux Cybersecurity Training**  
> A tool that evaluates password strength based on length, complexity, and common patterns — with a Python CLI and a standalone browser UI.

---

## 📁 Project Files

```
password-tool/
├── analyzer.py               # Core analysis logic (shared by CLI)
├── common_passwords.py       # ~200 common/leaked password blocklist
├── cli.py                    # Python CLI front-end
└── password_analyzer.html    # Standalone browser UI (no server needed)
```

---

## ⚙️ Requirements

| Requirement | Details |
|---|---|
| OS | Kali Linux (or any Debian/Ubuntu-based system) |
| Python | Python 3.6 or later (pre-installed on Kali) |
| Browser | Firefox / Chromium (pre-installed on Kali) |
| External packages | **None** — zero `pip install` required |

Check Python is installed:
```bash
python3 --version
```

---

## 🚀 Quick Start

### Option A — Browser UI (easiest)
```bash
firefox ~/password-tool/password_analyzer.html
```
Type a password → results update live. Nothing is sent anywhere.

### Option B — CLI (interactive, input hidden)
```bash
cd ~/password-tool
python3 cli.py
```

---

## 🖥️ CLI Usage

### Interactive mode *(recommended — hides your input)*
```bash
python3 cli.py
```
```
Password:          ← type here (hidden like sudo)
```

### Single password mode
```bash
python3 cli.py "MyP@ssword123!"
```
> ⚠️ This stores the password in your shell history — use only for testing.

### Batch file mode *(one password per line)*
```bash
python3 cli.py --file passwords.txt
```

### Test against Kali's rockyou wordlist
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz   # unzip once if needed
head -n 20 /usr/share/wordlists/rockyou.txt > sample.txt
python3 cli.py --file sample.txt
```

---

## 🌐 Web UI Usage

```bash
cd ~/password-tool
xdg-open password_analyzer.html
# or
firefox password_analyzer.html
```

- Type into the input box — strength meter updates instantly
- Click **show** to toggle password visibility
- All analysis runs locally in JavaScript — no network calls

---

## 📊 How It Works

The analyzer checks 5 things:

| Check | What it detects |
|---|---|
| **Length** | Under 8 chars (too short), under 12 (below recommended) |
| **Character classes** | Missing lowercase, uppercase, digits, or symbols |
| **Keyboard walks** | `qwerty`, `asdf`, `zxcv`, `1234` (forward & reversed) |
| **Sequential runs** | `abcd`, `zyxw`, `1234`, `9876` (4+ chars) |
| **Repeated chars** | `aaaa`, `1111`, `!!!` (3+ repeats) |
| **Common passwords** | Checked against ~200 known leaked/common passwords |

### Scoring

| Score | Label | Colour |
|---|---|---|
| 0 | Very Weak | 🔴 Red |
| 1 | Weak | 🟠 Orange |
| 2 | Fair | 🟡 Yellow |
| 3 | Strong | 🟢 Green |
| 4 | Very Strong | 💚 Bright Green |

### Entropy & Crack Time

Entropy is estimated as `length × log₂(pool_size)` where pool size grows with each character class used. Crack time assumes **10 billion guesses/second** (fast offline GPU attack on a weakly hashed password) — illustrative only.

---

## 🧪 Sample Output

```
Password: ******************
Strength: Very Strong  [██████████████████████████████]
Estimated entropy: 111.4 bits
Estimated offline crack time: ~110 trillion centuries

Issues found:
  - No major issues detected.
```

```
Password: **********
Strength: Very Weak  [██████░░░░░░░░░░░░░░░░░░░░░░░░]
Estimated entropy: 47.0 bits
Estimated offline crack time: instantly
⚠ This password appears in a common-password list.

Issues found:
  - Below the recommended minimum of 12 characters.
  - Uses only one type of character (only lowercase letters).
  - Contains a keyboard walk pattern (e.g. 'qwerty', 'asdf').
  - This is one of the most commonly used passwords.

Suggestions:
  - Aim for 12+ characters; consider a passphrase of 4-5 random words.
  - Add at least one uppercase letter.
  - Add at least one digit.
  - Add at least one symbol (e.g. ! @ # $ %).
  - Avoid adjacent keyboard keys typed in sequence.
  - Never reuse common passwords.
```

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `python3: command not found` | `sudo apt update && sudo apt install python3 -y` |
| `ModuleNotFoundError: No module named 'analyzer'` | All 3 Python files must be in the **same folder** |
| `xdg-open: command not found` | Use `firefox password_analyzer.html` directly |
| HTML page is blank | Enable JavaScript in your browser |
| `rockyou.txt` not found | Run `sudo gunzip /usr/share/wordlists/rockyou.txt.gz` first |

---

## ⚠️ Security Notes

- **This tool is for education only** — it does not store, transmit, or log any passwords
- Entropy estimates are theoretical upper bounds — recognisable patterns lower real-world strength
- The blocklist (~200 entries) covers common cases only; production systems should use a full breach database
- Crack-time estimates assume a **weak hash** — properly salted Argon2/bcrypt hashes are orders of magnitude slower to crack

---

## 📌 Best Practices (from NIST SP 800-63B)

- Use **12+ characters** minimum; longer is always better
- Use a **passphrase** of 4–5 random words (e.g. `correct-horse-battery-staple`)
- Use a **password manager** to generate and store unique passwords
- **Never reuse** passwords across different sites or services
- Enable **multi-factor authentication (MFA)** wherever available

---

## 📄 License

This project is for educational and training purposes.  
Built as **Task 1** of a Kali Linux cybersecurity training exercise.# Password_strength_analyzer_tool
