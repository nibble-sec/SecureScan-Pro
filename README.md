# 🛡️ SecureScan: AI Malware Analysis & Suspicious File Detection System

A hybrid malware detection tool for Windows executables (PE files). SecureScan combines three independent detection engines (heuristic analysis, a machine-learning model, and YARA rules) into a single risk score and verdict. It ships with two interfaces: a **Streamlit web app** and a **CustomTkinter desktop app**.

> Final year project. Built for educational and research purposes. It is **not** a replacement for a production antivirus.

---

## Features

- **Hybrid detection**: heuristic + machine learning + YARA signatures, merged into one 0–100 risk score
- **Machine learning engine**: LightGBM model trained on the [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) dataset, with malware family labels
- **Heuristic engine**: inspects PE structure for packers, high-entropy sections, and suspicious API imports
- **YARA engine**: custom rules for EICAR, malicious PDFs, Office macros, shellcode patterns, and more. Includes a pure-Python fallback if `yara-python` is not installed
- **SHA-256 hashing** of every scanned file
- **Scan history and quarantine log** stored in a local SQLite database
- **Two interfaces**: web dashboard (Streamlit) and desktop GUI (CustomTkinter)
- **Fully offline**: no files are uploaded to any external service

---

## How It Works

```
            ┌──────────────────┐
            │   Input file     │
            └────────┬─────────┘
     ┌───────────────┼────────────────┐
     ▼               ▼                ▼
┌──────────┐   ┌───────────┐   ┌─────────────┐
│Heuristic │   │ ML Engine │   │ YARA Engine │
│  Engine  │   │ (LightGBM)│   │             │
└────┬─────┘   └─────┬─────┘   └──────┬──────┘
     └───────┬───────┘                │
             ▼                        │
   0.4 × heuristic + 0.6 × ML         │
             └──────────┬─────────────┘
                        ▼
          final score = max(combined, YARA)
                        ▼
            CLEAN / SUSPICIOUS / MALICIOUS
```

### Detection engines

| Engine | File | What it does |
|---|---|---|
| Heuristic | `heuristic_engine.py` | Parses the PE file and scores it on packer section names (UPX, ASPack, VMProtect…), sections with entropy above 7.0, and suspicious API imports such as `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, and `URLDownloadToFile` |
| Machine learning | `ml_engine.py`, `features.py` | Extracts EMBER-style PE features and predicts malware probability and family using a LightGBM model |
| YARA | `yara_engine.py`, `rules/main.yar` | Matches signature rules and returns a risk score based on rule metadata |

### Verdict thresholds

| Final score | Verdict | Risk |
|---|---|---|
| 60 and above | 🔴 MALICIOUS | High (file is added to quarantine log) |
| 30 to 59 | 🟡 SUSPICIOUS | Medium |
| Below 30 | 🟢 CLEAN | Low |

---

## Project Structure

```
.
├── streamlit_app.py          # Web interface (Streamlit)
├── main.py                   # Desktop interface (CustomTkinter)
├── heuristic_engine.py       # Heuristic PE analysis
├── ml_engine.py              # LightGBM model wrapper
├── features.py               # EMBER-style PE feature extractor
├── yara_engine.py            # YARA scanner with Python fallback
├── colab_training_script.py  # Script to train the model on Google Colab
├── rules/
│   └── main.yar              # YARA rules
├── models/
│   ├── ember_model.txt       # Trained LightGBM model
│   └── family_mapping.json   # Class ID to malware family mapping
├── .streamlit/config.toml    # Streamlit settings
├── run_web_version.bat       # One-click launcher (Windows)
└── requirements.txt          # Python dependencies
```

---

## Installation

**Requirements:** Python 3.9 or newer.

```bash
# 1. Clone the repository
git clone https://github.com/YOUR-USERNAME/YOUR-REPO.git
cd YOUR-REPO

# 2. (Recommended) create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt
pip install streamlit        # needed for the web interface
```

> **Note on `yara-python`:** it needs build tools on some systems. If installation fails, the app still works. It automatically falls back to a lightweight pure-Python YARA rule matcher.

---

## Usage

### Web interface (Streamlit)

```bash
streamlit run streamlit_app.py
```

On Windows you can also double-click `run_web_version.bat`.

The dashboard has four sections:

- **📊 Overview**: total scans, threats, suspicious and clean counts, quarantined files
- **🔍 Analyze File**: upload an `.exe`, `.dll`, or `.sys` file and get the full report
- **📜 Scan Logs**: history of all previous scans
- **🛡️ Quarantine**: files flagged as malicious

### Desktop interface (CustomTkinter)

```bash
python main.py
```

The first run creates the local SQLite database (`scanner_data.db`) automatically.

---

## Training the Model

The included model was trained with `colab_training_script.py`:

1. Open [Google Colab](https://colab.research.google.com) and paste in the script
2. Run it. It downloads the EMBER2024 dataset and trains a LightGBM model
3. Download `ember_model.txt` and `family_mapping.json`
4. Place both in the `models/` folder

By default the script uses the smaller *challenge* split so it runs on free Colab. Switch the split to `"train"` in the script to train on the full dataset.

---

## Technologies Used

- **Python**: core language
- **LightGBM** and **scikit-learn**: machine learning
- **pefile**: PE file parsing
- **yara-python**: signature matching
- **Streamlit** and **CustomTkinter**: user interfaces
- **SQLite**: scan history and quarantine storage
- **pandas / NumPy**: data handling

---

## Limitations

- Analyzes **Windows PE files** only (`.exe`, `.dll`, `.sys`). Other file types are covered only by YARA rules and a basic size check
- The ML model is trained on a limited slice of EMBER2024 and recognizes a small set of malware families
- Static analysis only. Files are never executed, so behavior-based threats may be missed
- Heuristic rules can produce false positives on legitimately packed software

## Disclaimer

This project is for educational purposes. Do not rely on it as your only protection against malware. Handle real malware samples only in an isolated environment.

## Acknowledgements

- [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) dataset and `thrember` library
- [YARA](https://virustotal.github.io/yara/), [pefile](https://github.com/erocarrera/pefile), [LightGBM](https://github.com/microsoft/LightGBM)

## License

Add a license of your choice (for example MIT) in a `LICENSE` file.

