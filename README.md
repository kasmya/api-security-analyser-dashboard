# API Security Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/downloads/) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-brightgreen)](https://fastapi.tiangolo.com/) [![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5.1-orange)](https://scikit-learn.org/)

**Multi-layer API request security scanner** with Regex, YARA rules, and ML anomaly detection (Isolation Forest). Validates payloads, detects SQLi/XSS abuse, rate-limits IPs, and logs threats.

## 🚀 Features

- **Input Validation**: Pydantic schemas + size limits (10KB max)
- **Threat Detection**: Regex + YARA rules for SQLi, XSS, command injection
- **ML Anomaly Detection**: Isolation Forest flags zero-day patterns
- **Rate Limiting**: 10 requests/minute per IP
- **Live Dashboard**: Real-time logs + Chart.js anomaly trends
- **Production Logging**: JSON-formatted `anomalies.log`

## 🔍 How It Works
1. POST /analyze → Pydantic validation
2. Regex scan → "union select", "<script>", etc.
3. YARA rules → Advanced pattern matching
4. ML features → [length, params, entropy, rate]
5. Isolation Forest → Anomaly score (-1 = threat)
6. Rate limit check → 429 if abused
7. Log + Return results

## 📚 Tech Stack

| Component | Technology                      |
| --------- | ------------------------------- |
| Backend   | FastAPI, Pydantic               |
| ML        | scikit-learn (Isolation Forest) |
| Rules     | YARA, Regex                     |
| Frontend  | HTML/CSS/JS, Chart.js           |
| Logging   | JSON + file rotation            |

