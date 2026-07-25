<div align="center">

#  ARGUS
### AI-Powered Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange?style=flat-square&logo=tensorflow)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square&logo=fastapi)
![React](https://img.shields.io/badge/React-18-blue?style=flat-square&logo=react)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

*Argus Panoptes — the all-seeing guardian of Greek mythology — never slept and could see everything at once. That's exactly what this system does to your network.*

</div>

---

## What is Argus?

Argus is a **self-hosted, AI-driven Network Intrusion Detection System (NIDS)** that:

-  **Captures** live network traffic in real time
-  **Classifies** threats using Machine Learning (Random Forest + Autoencoder)
-  **Explains** every attack in plain English using a local LLM (Ollama/Mistral)
-  **Generates** professional incident reports automatically
-  **Displays** everything on a live React dashboard

> No cloud. No subscriptions. Runs 100% on your own machine.

---

##  Quick Demo

```bash
# Clone the repo
git clone https://github.com/Suvendu-ai/Argus.git
cd Argus

# Start everything with one command
docker-compose up
```

Then open: **http://localhost:3000**

---

##  Threats Argus Detects

| Attack Type       | Description                              |Severity|

|   DoS / DDoS      | Flood attacks that overwhelm your network| HIGH |
|   Port Scanning   |Reconnaissance attempts mapping your system|MEDIUM|
|   Brute Force     | Password/login cracking attempts          | HIGH |
|   R2L             | Remote to Local unauthorized access       | HIGH |
|   U2R             | Privilege escalation attacks            | CRITICAL |
| Zero-Day Anomalies| Unknown attacks caught by Autoencoder     | HIGH |
  
---

##  Architecture
Live Network Traffic
↓
core/capture.py ← Scapy packet capture
↓
core/extractor.py ← Flow-based feature extraction
↓
core/classifier.py ← Dual ML model inference
↙ ↘
Random Forest Autoencoder
(known attacks) (anomalies)
↘ ↙
llm/explainer.py ← Ollama/Mistral explanation
↓
llm/reporter.py ← Auto incident reports
↓
api/main.py ← FastAPI + WebSocket server
↓
dashboard/ ← React live dashboard

---

##  ML Models

| Model         | Type       | Accuracy   | Purpose                     |

| Random Forest | Supervised | **75.10%** | Classify known attack types |
| Autoencoder   |Unsupervised| **85.69%** | Detect unknown anomalies    |

Trained on the **NSL-KDD dataset** (125,973 network connections).

---

##  Getting Started

### Prerequisites
- Docker Desktop
- Ollama (for LLM explanations)

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/Suvendu-ai/Argus.git
cd Argus
```

**2. Install Ollama and pull Mistral**
```bash
# Install from https://ollama.com
ollama pull mistral
```

**3. Train the ML models (first time only)**
```bash
pip install -r requirements.txt
python ml/train_classifier.py
python ml/train_autoencoder.py
```

**4. Launch Argus**
```bash
docker-compose up
```

**5. Open the dashboard**

http://localhost:3000

---

## 📁 Project Structure
Argus/
├── core/
│ ├── capture.py # Live packet capture (Scapy)
│ ├── extractor.py # Feature extraction from flows
│ ├── classifier.py # ML inference bridge
│ └── anomaly.py # Anomaly detection logic
├── ml/
│ ├── train_classifier.py # Random Forest training
│ ├── train_autoencoder.py# Autoencoder training
│ └── models/ # Saved trained models
├── llm/
│ ├── explainer.py # LLM threat explanation
│ └── reporter.py # Incident report generation
├── api/
│ └── main.py # FastAPI backend + WebSockets
├── dashboard/ # React frontend (Vite)
├── data/
│ ├── raw/ # NSL-KDD dataset
│ └── processed/ # Extracted flow features
├── reports/ # Generated incident reports
├── Dockerfile # API Docker image
├── docker-compose.yml # Full stack deployment
└── requirements.txt

---

## 🛠️ Tech Stack

**Backend & ML**
- Python 3.11
- Scapy (packet capture)
- Scikit-learn (Random Forest)
- TensorFlow/Keras (Autoencoder)
- FastAPI + WebSockets
- Ollama + Mistral (local LLM)

**Frontend**
- React 18 + Vite
- Recharts (live charts)
- Lucide React (icons)

**Infrastructure**
- Docker + Docker Compose
- Nginx (dashboard serving)

**Dataset**
- NSL-KDD (125,973 labeled network connections)

---

## 📊 Sample Incident Report

Argus automatically generates professional incident reports:

ARGUS — Security Incident Report
Report ID : ARGUS-20260711_143022
Total Threats : 3
Risk Level :  HIGH

Threat #1 — DoS Attack
Source IP : 192.168.1.100
AI Analysis : "A TCP SYN flood attack was detected.
The attacker is overwhelming your server
with connection requests..."

---

## 🎯 Use Cases

- **Home network monitoring** — Run on your PC, watch your WiFi
- **Lab/college networks** — Deploy on a server, monitor the entire network  
- **Security research** — Study real attack patterns with ML
- **Portfolio project** — Demonstrates full-stack AI + security engineering

---

## 🔮 Future Improvements

- [ ] Email/Telegram alert notifications
- [ ] Geo-IP mapping of attack sources
- [ ] PCAP file analysis mode
- [ ] Scheduled automated reports
- [ ] Multi-network interface support

---

## 👨‍💻 Author

**Suvendu** — [@Suvendu-ai](https://github.com/Suvendu-ai)

Built as a portfolio project demonstrating:
AI/ML Engineering · Cybersecurity · Full-Stack Development · DevOps

---

## 📄 License

MIT License — free to use, modify and distribute.

---

<div align="center">

*Built with ❤️ | Powered by AI | Protected by Argus*

⭐ Star this repo if you found it useful!

</div>