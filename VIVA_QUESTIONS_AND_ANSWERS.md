# 🎓 CyberSentinel SOC Platform: Final Year Viva & Oral Defense Guide

This document is prepared to help you confidently answer questions from examiners, professors, and technical evaluators during your major project presentation and viva examination.

---

### Q1. What is the main objective of your project?
> **Answer:**  
> "My project is **CyberSentinel**, an academic prototype of an **AI-Powered Security Operations Center (SOC) Threat Detection and Incident Response Platform**.  
> In modern enterprise networks, thousands of security events occur every minute across computers, web servers, and firewalls. A human analyst cannot manually review every log.  
> CyberSentinel acts as a central security intelligence hub: it **collects** heterogeneous logs, **normalizes** them into a unified format, analyzes them using a **hybrid engine (deterministic rules + machine learning anomaly detection)**, correlates related events across time to reconstruct multi-stage attack kill-chains, calculates an objective **0–100 Risk Score**, and generates **actionable response recommendations** (such as automated firewall IP blocking and account lockouts) with human-in-the-loop analyst authorization."

---

### Q2. What is the fundamental architecture / pipeline of your project?
> **Answer:**  
> "The system follows a sequential 9-stage data processing pipeline:
> ```text
> 1. COLLECT      → Ingest raw logs from Linux auth, Apache/Nginx web servers, firewalls
> 2. NORMALIZE    → Convert heterogeneous logs into standardized JSON schema
> 3. DETECT       → Parallel evaluation: Rule Engine (known signatures) + ML Engine (novel deviations)
> 4. THREAT INTEL → Match against known Indicators of Compromise (IOC database)
> 5. RISK SCORE   → Calculate composite 0–100 risk score based on rule weight, anomaly score, and asset criticality
> 6. CORRELATE    → Cluster individual alerts by IP, user, and time to reconstruct the attack story
> 7. ALERT        → Raise prioritized alerts (Low, Medium, High, Critical)
> 8. INVESTIGATE  → Display timeline, MITRE ATT&CK mapping, and evidence on the SOC dashboard
> 9. RESPOND      → Recommend active containment (e.g. iptables drop, account disable) requiring analyst approval
> ```"

---

### Q3. Why is Log Normalization necessary?
> **Answer:**  
> "Different operating systems and network appliances write logs in completely different formats. For example:
> - A Linux auth log writes: `Failed password for admin from 192.168.1.50 port 22 ssh2`
> - An Apache web log writes: `192.168.1.50 - - [15/Oct/2026:12:00:00] "POST /login" 401 512`
> - A firewall writes: `FIREWALL DROP src=192.168.1.50 dst=192.168.1.10 proto=TCP dport=445`
>
> If detection engines had to handle each proprietary format separately, writing detection logic would be slow and prone to errors. Normalization extracts standard attributes—**Timestamp, Source, Source IP, Destination Port, User, Event Type, Target Asset, and Severity**—so downstream detection modules can process all logs uniformly."

---

### Q4. What is the "AI / Machine Learning" component in your project?
> **Answer:**  
> "The AI component is an **unsupervised anomaly detection model based on the Isolation Forest algorithm** from Scikit-Learn.
>
> While rules catch known attack patterns (like >4 failed logins in 5 minutes), attackers often use novel techniques or slow, low-volume behavior that bypasses static thresholds.
>
> Our Isolation Forest model monitors a 6-dimensional behavioral feature vector:
> 1. `failed_login_count` (in recent time window)
> 2. `requests_per_minute` (traffic rate)
> 3. `unique_ports_accessed` (port diversity/sweep index)
> 4. `data_transferred_kb` (volume / exfiltration indicator)
> 5. `is_external_ip` (binary flag for private vs public IP)
> 6. `is_admin_attempt` (binary flag for sensitive file/command access)
>
> The model learns the baseline of normal enterprise operations and scores incoming events with an **Anomaly Score from 0.00 (completely normal) to 1.00 (highly anomalous)**."

---

### Q5. Why did you choose Isolation Forest instead of supervised classification (like SVM, Random Forest, or Neural Networks)?
> **Answer:**  
> "In cybersecurity operations:
> 1. **Data Imbalance & Lack of Labels:** 99.9% of enterprise logs represent benign operational traffic, and true attack logs are extremely rare. Furthermore, newly discovered zero-day attacks do not have pre-existing training labels.
> 2. **Unsupervised Outlier Isolation:** Isolation Forest explicitly isolates anomalies instead of profiling normal points. Because anomalies are 'few and different', they are isolated closer to the root of random decision trees (having shorter average path lengths).
> 3. **Linear Time Complexity:** Isolation Forest has an $O(n)$ time complexity and low memory footprint, which makes it fast enough for real-time streaming event inference."

---

### Q6. Why not use *only* Machine Learning or *only* Rule-Based Detection?
> **Answer:**  
> "This is a classic trade-off in security engineering:
> - **Rules alone** are fast and produce zero false positives for known signatures (e.g. matching an exact malicious IP or known sudo escalation). However, rules are blind to zero-day attacks or stealthy variations that stay just under the threshold.
> - **ML alone** can discover novel anomalous patterns, but without domain rules, it can suffer from higher false positive rates when legitimate user behavior fluctuates (e.g., an employee working late or uploading a large file).
>
> In CyberSentinel, we implement a **Hybrid Engine**:
> - When Rule + ML agree: Risk is elevated to **CRITICAL** (high confidence).
> - When only ML flags an event: Risk is marked **SUSPICIOUS/MEDIUM**, prompting analyst review without generating alert fatigue."

---

### Q7. How is your 0–100 Risk Score calculated?
> **Answer:**  
> "We use a multi-factor risk scoring formula that weighs four distinct dimensions:
> $$\text{Risk Score} = \text{Rule Weight} (35) + \text{ML Anomaly Score} \times 35 + \text{Threat Intel Hit} (15) + \text{Asset Criticality} (15)$$
>
> - **Rule Component (Max 35 pts):** Severity assigned to the triggered signature.
> - **ML Anomaly Component (Max 35 pts):** Continuous anomaly score $(0.0 \text{ to } 1.0) \times 35$.
> - **Threat Intelligence (15 pts):** Added if source IP is present in known adversary IOC databases (e.g. Tor exit nodes, Mirai botnet).
> - **Asset Criticality (Max 15 pts):** Domain controllers and database servers carry higher asset weight than secondary workstations.
>
> **Tiers:**
> - `0 – 25`: Low (Informational)
> - `26 – 50`: Medium (Routine Investigation)
> - `51 – 75`: High (Prioritized Security Alert)
> - `76 – 100`: Critical (Urgent Incident Containment)"

---

### Q8. What is Event Correlation, and why is it important?
> **Answer:**  
> "Event Correlation connects individual, seemingly disconnected alerts into a single cohesive story or **Incident**.
>
> For example:
> 1. At 12:01, IP `185.220.101.5` performs a Port Scan (Reconnaissance).
> 2. At 12:03, the same IP attempts multiple failed SSH logins (Brute Force).
> 3. At 12:05, a successful login occurs (Credential Compromise).
> 4. At 12:06, the account executes `sudo /etc/shadow` (Privilege Escalation).
>
> If treated individually, the analyst receives 4 separate low-to-medium alerts.  
> Our **Correlation Engine** groups these alerts by source IP and user within a sliding 15-minute window, identifies the **MITRE ATT&CK progression**, and raises a single **Critical Incident: Multi-Stage Account Takeover & Privilege Escalation**."

---

### Q9. Why does your Incident Response require human approval instead of 100% full automation?
> **Answer:**  
> "In real-world cybersecurity, fully automated active response can cause catastrophic business disruption if triggered by a false positive (for example, accidentally blacklisting a corporate gateway or locking out an executive's account during business hours).
>
> Therefore, CyberSentinel employs a **Human-in-the-Loop (HITL)** architecture:
> 1. The Response Engine automatically synthesizes the recommended containment command (e.g., `iptables -I INPUT -s <IP> -j DROP` or `usermod --expiredate 1 <user>`).
> 2. The analyst reviews the correlated evidence and risk score on the SOC dashboard.
> 3. The analyst clicks **'Approve & Enforce Response'** with one click.
> 4. The system executes the containment action, updates firewall ACLs, marks the incident as **CONTAINED**, and logs an immutable audit trail."

---

### Q10. What technologies did you use to build the platform?
> **Answer:**  
> - **Backend:** Python 3.14 & Django 5.0 (REST Framework for APIs, modular engine architecture).
> - **Machine Learning:** Scikit-Learn (Isolation Forest algorithm), NumPy, Pandas, Joblib.
> - **Database:** Relational schema (SQLite for development/demonstration, easily swappable to PostgreSQL).
> - **Frontend:** Modern responsive dark-themed SOC Command Dashboard built with HTML5, Vanilla CSS, and Chart.js for real-time visual analytics.
> - **Log Simulation:** Custom attack simulation generator implementing SSH brute-force, Nmap port scanning, credential stuffing, and multi-stage APT kill-chains.

---

### Q11. How can you demonstrate that your system works during this viva?
> **Answer:**  
> "We built an interactive **Attack Simulation Lab** directly into the platform dashboard:
> 1. I can click **'💥 SSH Brute Force'** &rarr; The dashboard immediately shows the raw auth logs, the rule engine trigger (RULE-01), the rising ML anomaly score, and an alert.
> 2. I can click **'🚨 Full APT Kill-Chain'** &rarr; The Correlation Engine detects the multi-stage progression from reconnaissance to root privilege escalation, raises a Critical Incident (`INC-XXXX`), and calculates a risk score of 75+.
> 3. I can then open the Incident, inspect the evidence, and click **'Approve & Enforce Action'**, which executes the firewall block and updates the incident lifecycle to **CONTAINED** in real time."

---

### Q12. What is the difference between your Isolation Forest ML and your Google Gemini LLM Assistant?
> **Answer:**  
> "Our platform implements AI at two complementary layers:
> 1. **Detection Layer (Isolation Forest - Classical Unsupervised ML):**
>    - Evaluates numerical behavioral vectors in real time (milliseconds per log).
>    - Calculates continuous mathematical anomaly scores (0.00 to 1.00) without sending internal raw logs across the network.
> 2. **Cognitive / Decision Layer (Google Gemini LLM):**
>    - Acts as the senior tier-3 SOC analyst.
>    - Ingests correlated telemetry, explains multi-stage attack patterns in plain English, and provides reasoned **ALLOW vs BLOCK** recommendations with legal and operational justifications.
>
> This separation of concerns ensures rapid, privacy-preserving threat detection at the edge coupled with deep generative reasoning for complex incidents."

