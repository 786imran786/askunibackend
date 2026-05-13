# 🚀 AskUNI — Realtime University Q&A & Forum Platform

AskUNI is a scalable full-stack university community platform inspired by Reddit, StackOverflow, and Discord.  
It enables students to ask questions, post answers, join forums, interact in realtime, and collaborate within a university ecosystem.

The platform focuses on:
- realtime communication
- scalable backend architecture
- optimized APIs
- modern authentication
- distributed systems concepts

---

# 🌟 Features

## 🔐 Authentication & Security
- JWT Authentication
- Google OAuth Login
- OTP Email Verification
- Password Hashing
- Protected APIs
- Role-Based Access
- Rate Limiting using Redis
- Secure Token Validation

---

## 🧠 Question & Answer System
- Create Questions
- Post Answers
- Rich Question Feed
- Voting System
- Tags & Categorization
- Realtime Feed Updates
- Pagination Support
- Optimized Query Handling

---

## 💬 Forum System
- Create Forums
- Join/Leave Forums
- Realtime Forum Messaging
- Forum Member Management
- Live Message Broadcasting
- SSE-Based Realtime Updates

---

## ⚡ Realtime Architecture
- Redis Pub/Sub
- Server-Sent Events (SSE)
- Cross-Instance Event Broadcasting
- Live Question Feed
- Instant Notifications
- Distributed Realtime Communication

---

## 📦 Storage & Media
- Supabase Storage Integration
- Image Upload Support
- Optimized File Handling
- Web-Friendly Media Delivery

---

## 🚀 Performance Optimizations
- Redis Caching
- Pagination
- Database Indexing
- Reduced N+1 Queries
- Optimized API Responses
- Background Task Handling
- Production-Ready Architecture

---

# 🏗️ Tech Stack

## Frontend
- React.js / Next.js
- Vercel Deployment

## Backend
- Flask
- Gunicorn
- REST APIs
- SSE Realtime System

## Database
- Supabase PostgreSQL

## Cache & Realtime
- Redis (Upstash)

## Authentication
- JWT
- Google OAuth

## Deployment
- Render
- Vercel

---

# ⚡ Architecture

```text
Frontend (Vercel)
        ↓
Flask API + Gunicorn (Render)
        ↓
Redis Cache + Pub/Sub
        ↓
Supabase PostgreSQL
```

---

# 🌟 Realtime Flow

```text
User posts question
        ↓
Flask API stores in Supabase
        ↓
Redis publishes event
        ↓
All backend instances receive event
        ↓
SSE broadcasts update
        ↓
Connected users instantly see update
```

---

# 📂 Project Structure

```text
askuni-backend/
│
├── app.py
├── routes/
│   ├── auth.py
│   ├── profile.py
│   ├── questions.py
│   ├── forums.py
│
├── services/
│   ├── auth_service.py
│   ├── question_service.py
│   ├── forum_service.py
│
├── cache/
│   ├── redis_client.py
│
├── realtime/
│   ├── sse.py
│   ├── redis_pubsub.py
│
├── utils/
│   ├── helpers.py
│   ├── validators.py
│
├── uploads/
├── templates/
├── static/
│
├── requirements.txt
└── README.md
```

---

# 🔥 Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/yourusername/askuni.git

cd askuni
```

---

## 2️⃣ Create Virtual Environment

### Windows

```bash
python -m venv venv

venv\Scripts\activate
```

### Linux / WSL

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ⚙️ Environment Variables

Create `.env`

```env
SECRET_KEY=your_secret_key

JWT_SECRET_KEY=your_jwt_secret

SUPABASE_URL=your_supabase_url

SUPABASE_KEY=your_supabase_key

REDIS_URL=rediss://default:password@host:6379

GOOGLE_CLIENT_ID=your_google_client_id

GOOGLE_CLIENT_SECRET=your_google_client_secret

MAIL_USERNAME=your_email

MAIL_PASSWORD=your_password
```

---

# 🚀 Run Project

## Development

```bash
python app.py
```

---

## Production

```bash
gunicorn -w 4 -k gthread app:app
```

---

# 🌟 Redis Setup

Using Upstash Redis:

1. Create Redis database
2. Copy `REDIS_URL`
3. Add to `.env`

Example:

```env
REDIS_URL=rediss://default:password@host:6379
```

---

# 🌟 API Features

## Authentication APIs
- Register
- Login
- Google Login
- OTP Verification
- Forgot Password

---

## Question APIs
- Create Question
- Get Feed
- Get Question Details
- Vote Question
- Post Answer

---

## Forum APIs
- Create Forum
- Join Forum
- Send Messages
- Realtime Updates

---

# ⚡ Performance Improvements

Implemented:
- Redis caching
- Redis Pub/Sub
- SSE optimization
- Pagination
- Background threading
- Query optimization
- Database indexing
- Reduced API payloads

---

# 🔥 Scalability Considerations

Current architecture supports:
- distributed realtime communication
- scalable caching
- multi-instance backend deployment
- optimized DB interactions

Future improvements:
- WebSocket migration
- Kubernetes deployment
- CDN optimization
- Async task queues
- AI-powered moderation

---

# 📊 Production Optimizations

- Gunicorn Workers
- Redis Realtime Layer
- API Caching
- Optimized DB Queries
- Environment-Based Config
- SSE Reconnect Handling
- Background Email Sending

---

# 🛡️ Security Features

- JWT Authentication
- Secure Password Hashing
- Token Validation
- Input Sanitization
- Protected Routes
- Rate Limiting
- Secure Upload Validation

---

# 🌟 Learning Outcomes

This project helped explore:
- distributed systems
- realtime architectures
- backend optimization
- caching strategies
- REST API design
- authentication systems
- scalable backend engineering

---

# 👨‍💻 Author

Md Imran Siddiqui

Computer Engineering Student  
Backend Developer | Realtime Systems Enthusiast

---

# ⭐ Support

If you like this project:

- Star the repository
- Fork the project
- Contribute improvements

---

# 📜 License

This project is licensed under the MIT License.
