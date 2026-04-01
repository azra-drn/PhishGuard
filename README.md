# PhishGuard 

PhishGuard is an explainable rule-based phishing detection system designed to analyse URLs, sender information, and message content in real time. The system provides clear' results through an interactive dashboard, helping users understand why a link is considered phishing.

---

##  Features

- Real-time phishing analysis  
- Interactive dashboard with visualisations  
- Rule-based detection engine (explainable)  
- Risk scoring system (Low / Medium / High)  
- Evaluation metrics (Accuracy, Precision, Recall, F1 Score)  
- Scan history tracking  
- Rule explanations and recommendations  

---

##  System Architecture

PhishGuard follows a full-stack architecture:

User → React Frontend → FastAPI Backend → Rule Engine → SQLite Database

- Frontend: React + Recharts  
- Backend: FastAPI  
- Database: SQLite (via SQLAlchemy)  
- Validation: Pydantic  

---

##  How It Works

1. User submits:
   - URL  
   - Sender email  
   - Subject  
   - Message content  

2. Backend processes input using a rule-based detection engine

3. Each rule contributes a score based on phishing indicators:
   - Suspicious URL structure  
   - Domain anomalies  
   - Urgent language  
   - Credential requests  

4. Final classification:
   - Score < 30 → Legitimate (Low Risk)  
   - Score ≥ 30 → Phishing (Medium/High Risk)  

5. Results are:
   - Stored in database  
   - Visualised in dashboard  

---

## Dashboard Features

- Risk Distribution (Pie Chart)  
- Top Triggered Rules (Bar Chart)  
- Score Trends (Line Chart)  
- Scan History Table  
- Evaluation Metrics (Accuracy, Precision, Recall, F1)  
- Actual vs Predicted Comparison  

---

##  Tech Stack

Frontend:
- React  
- Recharts  
- Axios  

Backend:
- FastAPI  
- Python  

Database:
- SQLite  
- SQLAlchemy  

Validation:
- Pydantic  

---

##  Evaluation

The system includes a built-in dataset for testing phishing detection performance.

Metrics used:
- Accuracy  
- Precision  
- Recall  
- F1 Score  

Confusion summary:
- True Positive  
- True Negative  
- False Positive  
- False Negative  

---

## How to Run the Project

1. Clone the repository

git clone https://github.com/azra-drn/PhishGuard.git  
cd PhishGuard  

---

2. Run Backend

cd backend  
python3 -m venv .venv  
source .venv/bin/activate  

pip install -r requirements.txt  

uvicorn app.main:app --reload  

Backend runs at:  
http://127.0.0.1:8000  

---

3. Run Frontend

cd frontend  
npm install  
npm run dev  

Frontend runs at:  
http://localhost:5173  

---

##  Project Structure

PhishGuard/  
│  
├── backend/  
│   ├── app/  
│   │   ├── main.py  
│   │   ├── rules.py  
│   │   ├── models.py  
│   │   ├── database.py  
│   │   ├── schemas.py  
│   │   └── crud.py  
│   └── requirements.txt  
│  
├── frontend/  
│   ├── src/  
│   │   ├── App.jsx  
│   │   └── components/  
│   └── package.json  
│  
└── README.md  

---

## Limitations

- Rule-based system may not detect highly sophisticated phishing attacks  
- Limited dataset for evaluation    

---

##  Future Improvements

- Integrate machine learning model for more accurate results  
- Expand dataset and add a feature for user can upload their own files to check 
- Add browser extension and able to check phishing in different platforms and formats    

---

##  Project Context

I have developed this project as part of a final-year Computer Science student, focusing on cybersecurity, explainability, and full-stack development.

---

##  Author

Azra Gulderen   

---

