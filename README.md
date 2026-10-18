# PhishLens – Full-Stack Phishing Detection System

## About the Project
PhishLens is a full-stack web application designed to analyze URLs and identify potential phishing threats. It uses a React frontend, Flask backend, and MySQL database to provide URL risk analysis.

## Features
- URL analysis for potential phishing threats
- Risk classification: Low, Medium, and High
- Risk score and analysis results
- Analysis history
- Dataset management
- REST API integration between frontend and backend

## Technologies Used
- **Frontend:** React, Vite, JavaScript, CSS
- **Backend:** Python, Flask
- **Database:** MySQL
- **API:** REST API

## Project Structure
```text
PhishLens/
├── backend/
│   ├── app.py
│   └── requirements.txt
├── database/
│   └── schema.sql
├── frontend/
│   ├── src/
│   └── package.json
└── .gitignore
```

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/Shruti-patil05/PhishLens.git
cd PhishLens
```

### 2. Set Up the Backend
```bash
cd backend
python -m pip install -r requirements.txt
```

Configure your local `.env` file with your MySQL database settings before starting the backend.

Run the backend:
```bash
python app.py
```

### 3. Set Up the Frontend
Open a new terminal:
```bash
cd frontend
npm install
npm run dev
```

Open the local URL displayed by Vite in your browser.

## API Endpoints
- `GET /api/health` – Check backend health
- `POST /api/analyze` – Analyze a URL
- `GET /api/dataset` – Retrieve dataset information
- `GET /api/history` – Retrieve analysis history

## Disclaimer
PhishLens is an educational project for phishing awareness and URL risk analysis. Its results are indicative and should not be treated as a guarantee that a URL is safe or malicious.

## Author
Shruti Patil
