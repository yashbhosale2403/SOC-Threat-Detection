# 🛡️ CyberSentinel: AI-Powered SOC Threat Detection & Incident Response Platform

> **Final Year B.E. Computer Science & Engineering Capstone Project**  
> *Developed by: Yash*

---

## 📌 Project Overview

**CyberSentinel** is an academic prototype of an **AI-Powered Security Operations Center (SOC) Platform**. It addresses the challenge of alert fatigue and undetected intrusions in modern networks by providing a centralized command center that:

1. **Ingests & Normalizes heterogeneous security logs** from Linux authentication, Apache/Nginx web servers, firewalls, and endpoint devices into a unified JSON format.
2. **Performs Dual-Layer Threat Detection**:
   - **Deterministic Rule Engine:** Detects known attack signatures (SSH brute force, Nmap port scanning, suspicious off-hours login, root sudo escalation).
   - **Machine Learning Anomaly Engine:** Uses an unsupervised **Isolation Forest** model to detect behavioral deviations based on a 6-dimensional feature vector.
3. **Correlates Disparate Events:** Assembles multi-step attacks across time into cohesive incident stories mapped to the **MITRE ATT&CK** matrix.
4. **Calculates Composite Risk Scores (0–100):** Weighs Rule confidence, ML Anomaly score, Threat Intelligence (IOC database), and Target Asset Criticality.
5. **Recommends & Executes Active Response:** Proposes containment actions (Firewall IP Drop, Account Lockout, Endpoint Isolation) with **Human-in-the-Loop (HITL)** analyst approval.
6. **⚙️ Dynamic Detection Rule Builder:**
   - Security analysts can create custom detection signatures on-the-fly using the **"➕ Add Rule"** button.
   - Configure keyword pattern matches (e.g. `union select`, `cmd.exe`), event types, frequency thresholds, time windows, and risk weights.
   - Seamlessly evaluated alongside baseline built-in rules (RULE-01 to RULE-05).
7. **🤖 Google Gemini Generative AI Assistant (SOC Copilot):**
   - Provide your **Gemini API Key** in the UI to perform live, LLM-powered telemetry inspection.

   - Summarizes what is happening on the network in plain English.
   - For every active incident, delivers an explicit **[🚨 BLOCK / CONTAIN]** vs **[🟢 ALLOW / BENIGN]** verdict with technical justification and MITRE ATT&CK mapping.
   - Works online with Google Gemini 1.5/2.0 Flash, with an automatic offline heuristic fallback if running without internet.


---

## 🏗️ System Architecture & Pipeline

```text
       LOG SOURCES
 (Linux Auth, Web, Firewall)
            │
            ▼
┌───────────────────────────┐
│     LOG NORMALIZER        │  --> Standardizes raw lines to unified schema
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│   DUAL DETECTION STACK    │
│  ┌─────────────────────┐  │
│  │ Rule Engine         │  │  --> Checks deterministic thresholds (RULE-01 to RULE-05)
│  └─────────────────────┘  │
│  ┌─────────────────────┐  │
│  │ ML Anomaly Engine   │  │  --> Isolation Forest unsupervised behavioral inference
│  └─────────────────────┘  │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│   THREAT INTEL (IOCs)     │  --> Checks Tor exit nodes, botnet IPs, known adversary scanners
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│    RISK SCORING (0-100)   │  --> Combines Rule (35) + ML (35) + Threat Intel (15) + Asset (15)
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│  EVENT CORRELATION ENGINE │  --> Groups alerts by IP/User to build multi-stage incidents
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│       SOC DASHBOARD       │  --> Real-time charts, live log stream, alert triage
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│  ANALYST RESPONSE ACTION  │  --> 1-Click approval for Firewall IP Block & Account Lockout
└───────────────────────────┘
```

---

## 🛠️ Tech Stack

- **Backend Framework:** Python 3.14 / Django 5.0 & Django REST Framework
- **Machine Learning:** Scikit-Learn (`IsolationForest`), NumPy, Pandas, Joblib
- **Database:** SQLite (built-in zero configuration) / PostgreSQL compatible
- **Frontend / UI:** HTML5, Vanilla CSS3 (Custom Dark Cyber SOC Theme), JavaScript (Fetch API)
- **Visual Analytics:** Chart.js (bundled locally for 100% offline viva capability)

---

## 🚀 How to Run the Project (Quick Start)

### Method 1: Single-Click Launcher (Windows)
Double-click `run_project.bat` in the project root folder.  
It will automatically run migrations, seed initial demo data, and open `http://127.0.0.1:8000/` in your browser.

---

### Method 2: Manual Command Line

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run database migrations:**
   ```bash
   python manage.py migrate
   ```

3. **Seed initial demonstration data:**
   ```bash
   python seed_data.py
   ```

4. **Start the development server:**
   ```bash
   python manage.py runserver 127.0.0.1:8000
   ```

5. **Open your browser:**
   Navigate to: **`http://127.0.0.1:8000/`**

---

## 🎯 How to Demonstrate in the Viva / Project Evaluation

Follow this 3-minute demonstration script for your examiners:

1. **Show the Threat Overview Dashboard:**
   - Point out the real-time KPI cards: **Ingested Logs**, **Active Alerts**, **Critical Incidents**, and **Containment Rate**.
   - Explain the charts: Threat Activity by Category, Top Malicious IPs, and Detection Engine Split (Rule vs ML vs Hybrid).

2. **Execute a Live Attack Simulation:**
   - Click the **"💥 SSH Brute Force"** button on the dashboard banner.
   - Show how 5 failed login attempts from IP `192.168.1.150` are ingested, parsed, and immediately flagged with **RULE-01: Authentication Brute-Force**.
   - Point out the **ML Anomaly Score** calculated by the Isolation Forest.

3. **Demonstrate Multi-Stage Event Correlation:**
   - Click **"🚨 Full APT Kill-Chain"**.
   - Show how the correlation engine connects Reconnaissance &rarr; Brute Force &rarr; Breached Login &rarr; Sudo Root Escalation into a single correlated incident:  
     `Multi-Stage Attack: Account Takeover & Privilege Escalation (185.220.101.5)`.

4. **Demonstrate Human-in-the-Loop Incident Response:**
   - Switch to the **Incident Management** tab.
   - Click **"Review Response"** on the open incident.
   - Review the system's automated recommendation: `Block source IP 185.220.101.5 on perimeter firewall`.
   - Click **"Approve & Enforce Action"**.
   - Show that the firewall command (`iptables -I INPUT 1 -s 185.220.101.5 -j DROP`) is logged and the incident status transitions to **CONTAINED**.

---

## 📁 Project Directory Structure

```text
project/
├── manage.py                       # Django management executable
├── requirements.txt                # Python dependencies
├── run_project.bat                 # 1-click Windows runner
├── seed_data.py                    # Demonstration database seeder
├── project.txt                     # Original project requirements specification
├── README.md                       # Main documentation & run instructions
├── VIVA_QUESTIONS_AND_ANSWERS.md   # Complete oral viva defense guide
│
├── cybersentinel/                  # Project configuration
│   ├── settings.py                 # App settings, static paths, apps
│   ├── urls.py                     # Root URL routing
│   └── wsgi.py
│
├── core/                           # Primary SOC application
│   ├── models.py                   # LogEvent, Alert, Incident, ResponseAction, IOC
│   ├── views.py                    # Dashboard view & REST API endpoints
│   ├── serializers.py              # DRF serialization models
│   ├── urls.py                     # API routes (/api/stats/, /api/simulate/, etc.)
│   ├── admin.py                    # Django Admin registration
│   │
│   ├── engine/                     # SOC Intelligence Engine modules
│   │   ├── collector.py            # Log ingestion & regex normalizer
│   │   ├── rules.py                # Rule-based threat detection (RULE-01 to RULE-05)
│   │   ├── ml_detector.py          # Isolation Forest feature extraction & inference
│   │   ├── risk_scorer.py          # 0-100 Composite risk scoring formula
│   │   ├── correlation.py          # Multi-stage kill-chain event correlation
│   │   ├── responder.py            # Containment action handler (iptables, usermod)
│   │   ├── simulator.py            # Live attack simulation generators
│   │   ├── threat_intel.py         # Known IOC database lookup
│   │   └── pipeline.py             # End-to-end pipeline orchestrator
│   │
│   └── ml_models/                  # Machine learning artifacts
│       ├── train_model.py          # Script to train Isolation Forest baseline
│       ├── isolation_forest.pkl    # Serialized Isolation Forest model
│       └── feature_scaler.pkl      # Serialized StandardScaler
│
├── templates/
│   └── dashboard.html              # Unified SOC Analyst Command Center
│
└── static/
    ├── css/
    │   └── soc_style.css           # Custom dark cyber SOC dashboard stylesheet
    └── js/
        ├── dashboard.js            # Real-time polling, Chart.js, response modals
        └── chart.min.js            # Offline Chart.js library
```

---

## 🔑 Administrative Access

- **SOC Dashboard:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Django Admin Console:** [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/)
  - **Username:** `admin`
  - **Password:** `admin123`
