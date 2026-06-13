# Digital Evidence Tracker

> A secure C++17 application for managing digital forensic evidence — featuring role-based access control, AES-256 encryption, RSA-2048 digital signatures, a full chain-of-custody audit trail, and a Qt6 GUI.
---

## Features

| Feature | Detail |
|---|---|
| Authentication | Login / Register with SHA-256 hashed passwords |
| Roles | Investigator · Admin · Officer (RBAC enforced on every action) |
| Evidence | Add, search by Case ID, search by Evidence ID |
| AES-256-CBC | Evidence description + location encrypted at rest |
| RSA-2048 Signatures | Every custody log entry is signed and verified |
| Custody Logs | Full chain-of-custody with signature verification |
| Audit Trail | Every action logged with user, role, result, and timestamp |
| Reports | Plain-text case report + audit trail report |
| Interface | Qt6 GUI |

---

## Requirements

- **Qt6** (Widgets module) with **MinGW 64-bit** toolchain — [Download Qt Installer](https://www.qt.io/download-qt-installer)
- **OpenSSL 3.x** for Windows (MinGW)
  - Bundled with Qt at `D:\Qt\Tools\OpenSSLv3\Win_x64`, **or**
  - Install via [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html) (Win64 full installer, not Light)
- **SQLite amalgamation** (`sqlite3.c` + `sqlite3.h`) — [Download from sqlite.org](https://sqlite.org/download.html)

---

## Project Structure

```
digital-evidence-tracker/
├── CMakeLists.txt
├── sqlite3/                    ← create this folder manually
│   ├── sqlite3.c               ← download from sqlite.org
│   └── sqlite3.h
├── User.h / User.cpp
├── Database.h / Database.cpp
├── Evidence.h / Evidence.cpp
├── AuthSystem.h / AuthSystem.cpp
├── EvidenceTracker.h / EvidenceTracker.cpp
├── ReportGenerator.h / ReportGenerator.cpp
├── EvidenceTrackerGUI.h / EvidenceTrackerGUI.cpp
└── main.cpp
```

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/digital-evidence-tracker.git
cd digital-evidence-tracker
```

### 2. Add SQLite

Download the [SQLite amalgamation](https://sqlite.org/download.html), then extract `sqlite3.c` and `sqlite3.h` into a `sqlite3/` folder in the project root.

### 3. Open in Qt Creator

Open Qt Creator → **File → Open File or Project** → select `CMakeLists.txt`

### 4. Set the Kit

Go to **Projects → Build & Run** and select your **Qt 6.x MinGW 64-bit** kit.
If no kit exists: **Preferences → Kits → Add** → choose the MinGW compiler.

### 5. Configure CMake

If paths aren't detected automatically, pass them explicitly:

```bash
cmake .. \
  -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH="D:/Qt/6.x.x/mingw_64" \
  -DOPENSSL_ROOT_DIR="D:/Qt/Tools/OpenSSLv3/Win_x64"
```

Replace paths with your actual Qt and OpenSSL installation locations.

### 6. Build and Run

In Qt Creator, press **Ctrl+B** to build and the green **Run** button to launch.

Or from a terminal:

```bash
mkdir build && cd build
cmake .. -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH="D:/Qt/6.x.x/mingw_64" \
  -DOPENSSL_ROOT_DIR="D:/Qt/Tools/OpenSSLv3/Win_x64"
mingw32-make
./evidence_tracker.exe
```

---

## Roles & Permissions

| Action | Investigator | Admin | Officer |
|---|:---:|:---:|:---:|
| Register users | — | ✔ | — |
| Add evidence | ✔ | ✔ | — |
| Search evidence | ✔ | ✔ | ✔ |
| View custody logs | ✔ | ✔ | ✔ |
| View audit trail | — | ✔ | — |
| Generate case report | ✔ | ✔ | — |
| Generate audit report | — | ✔ | — |

---

## Cryptography

This project uses the **modern EVP API** (OpenSSL 3.x compatible). All deprecated OpenSSL 1.x calls have been removed.

| Purpose | API Used |
|---|---|
| Password hashing | `EVP_Digest` with SHA-256 |
| RSA key generation | `EVP_PKEY_CTX` + `EVP_PKEY_keygen` |
| Digital signatures | `EVP_DigestSign` / `EVP_DigestVerify` |
| AES-256-CBC encryption | `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex` |

---

## Troubleshooting

| Error | Fix |
|---|---|
| `[ERROR] SQLite not found!` | Create the `sqlite3/` folder and place `sqlite3.c` + `sqlite3.h` inside it |
| `Could not find Qt6` | Pass `-DCMAKE_PREFIX_PATH="D:/Qt/6.x.x/mingw_64"` to cmake |
| `Could not find OpenSSL` | Pass `-DOPENSSL_ROOT_DIR="D:/Qt/Tools/OpenSSLv3/Win_x64"` to cmake |
| App crashes (missing DLLs) | Run `windeployqt evidence_tracker.exe` from the Qt MinGW bin folder, or copy `libssl-3-x64.dll` + `libcrypto-3-x64.dll` next to the exe |

---

## License

```
MIT License

Copyright (c) 2026 [Laiba Maqbool]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
