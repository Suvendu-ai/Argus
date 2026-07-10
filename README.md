Overview

ARGUS is designed to analyze network traffic data and identify suspicious activities such as intrusions, abnormal patterns, and potential cyber attacks.

It combines:

🔥 FastAPI backend
🤖 Machine Learning models
📊 Interactive dashboard (frontend)
🧠 Features
✅ Real-time network anomaly detection
✅ Machine Learning-based classification
✅ FastAPI REST API
✅ Interactive dashboard visualization
✅ Modular project structure
✅ Scalable architecture
🗂️ Project Structure
ARGUS/
│── api/           # FastAPI backend
│── core/          # ML classifier logic
│── ml/            # Trained models
│── dashboard/     # Frontend UI
│── reports/       # Generated reports
│── config/        # Config files
│── requirements.txt
│── README.md
⚙️ Installation
1️⃣ Clone Repository
git clone https://github.com/Suvendu-ai/Argus.git
cd Argus
2️⃣ Create Virtual Environment
python -m venv venv

Activate:

Windows

venv\Scripts\activate

Mac/Linux

source venv/bin/activate
3️⃣ Install Dependencies
pip install -r requirements.txt
▶️ Running the Project
🔹 Run Backend (FastAPI)
cd api
uvicorn main:app --reload

API will run at:
👉 http://127.0.0.1:8000

Swagger Docs:
👉 http://127.0.0.1:8000/docs

🔹 Run Frontend (Dashboard)
cd dashboard
npm install
npm run dev
🔗 API Example

POST /predict

{
  "src_ip": "192.168.1.1",
  "dst_ip": "192.168.1.2",
  "protocol": "TCP"
}
📊 Machine Learning
Model: Autoencoder (Anomaly Detection)
Accuracy: ~85.69%
Detects abnormal network patterns
🚀 Deployment
Backend: Render
Frontend: Vercel
🧑‍💻 Author

Suvendu Sekhar Rath

🎓 B.Tech Student
💻 Machine Learning & Web Development Enthusiast
🌟 Future Improvements
🔹 Real-time packet capture integration
🔹 Advanced threat classification
🔹 User authentication
🔹 Cloud deployment scaling
📜 License

This project is open-source and available under the MIT License.
