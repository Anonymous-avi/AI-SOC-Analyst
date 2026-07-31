# 🛡️ AI SOC Analyst

> **An AI-powered Security Operations Center (SOC) Copilot** that automates log analysis, detects cyber threats, enriches Indicators of Compromise (IOCs), maps attacks to the MITRE ATT&CK framework, generates AI-powered incident summaries, and creates downloadable PDF incident reports.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-Frontend-61DAFB?logo=react)
![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green?logo=mongodb)
![Vercel](https://img.shields.io/badge/Frontend-Vercel-black?logo=vercel)
![Render](https://img.shields.io/badge/Backend-Render-46E3B7)

---

## 🌐 Live Demo

### 🚀 Frontend
**https://ai-soc-analyst-ebon.vercel.app/**

### ⚙️ Backend API
**https://ai-soc-analyst-aphj.onrender.com/**

### 📚 API Documentation (Swagger)
**https://ai-soc-analyst-aphj.onrender.com/docs**

> **Note:** The backend is hosted on Render's free tier. If it has been inactive, the first request may take **30–60 seconds** while the service wakes up.

---

# 📖 Overview

AI SOC Analyst is an intelligent cybersecurity assistant designed to help Security Operations Centers analyze logs, identify security incidents, enrich threat intelligence, and generate investigation reports automatically.

Instead of manually reviewing thousands of logs, analysts can simply upload log files and receive:

- Security alerts
- IOC extraction
- Threat intelligence enrichment
- MITRE ATT&CK mapping
- AI-generated incident summaries
- Downloadable PDF reports

---

# ✨ Features

- 📂 Upload security log files
- 🔍 Automatic log parsing & normalization
- 🚨 Brute Force attack detection
- 🛣️ Path Traversal detection
- 🌐 IOC (Indicators of Compromise) extraction
- 🧠 AI-powered incident summaries
- 🛡️ MITRE ATT&CK mapping
- 📊 Threat scoring
- 📄 Downloadable PDF incident reports
- 💾 MongoDB Atlas integration
- 🌍 Fully deployed full-stack application

---

# 🏗️ Tech Stack

## Frontend
- React.js
- Vite
- CSS

## Backend
- FastAPI
- Python
- Pydantic
- Uvicorn

## Database
- MongoDB Atlas

## Deployment
- Vercel (Frontend)
- Render (Backend)

---

# ⚙️ System Architecture

```
                User
                  │
                  ▼
        React Frontend (Vercel)
                  │
                  ▼
        FastAPI Backend (Render)
                  │
                  ▼
            MongoDB Atlas
                  │
                  ▼
     Detection & AI Processing Engine
```

---

# 🔄 Workflow

1. Upload a log file.
2. Parse and normalize logs.
3. Detect security incidents.
4. Extract Indicators of Compromise (IOCs).
5. Enrich threat intelligence.
6. Map attacks to MITRE ATT&CK.
7. Calculate threat score.
8. Generate AI-powered summary.
9. Download PDF incident report.

---

# 📁 Project Structure

```
AI-SOC-Analyst/
│
├── backend/
│   ├── app/
│   ├── routers/
│   ├── services/
│   ├── models/
│   ├── schemas/
│   └── main.py
│
├── frontend/
│   ├── src/
│   ├── components/
│   ├── pages/
│   └── api/
│
└── README.md
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/Anonymous-avi/AI-SOC-Analyst.git
```

## Backend

```bash
cd backend

pip install -r requirements.txt

uvicorn main:app --reload
```

---

## Frontend

```bash
cd frontend

npm install

npm run dev
```

---

# 📸 Screenshots

> Add screenshots of:
>
> - Dashboard
> - Upload Logs
> - Alerts
> - AI Summary
> - PDF Report

---

# 🎯 Future Improvements

- User Authentication
- Real-time Monitoring
- Additional Threat Detection Rules
- SIEM Integrations
- Email Notifications
- Interactive Analytics Dashboard

---

# 👨‍💻 Author

**Avika Goel**

Computer Science Engineering Student

Passionate about Cybersecurity, AI, Machine Learning, and Full Stack Development.

---

# ⭐ If you found this project helpful

Please consider giving this repository a ⭐ on GitHub!