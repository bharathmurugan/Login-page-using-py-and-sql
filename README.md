Glassgate Authentication System
About

Glassgate Authentication System is a secure full-stack authentication web application built with Python Flask and MySQL. It provides user registration, login, session management, password security, account lockout protection, live online presence, member management, and real-time-style chat features through a modern glassmorphism interface.

The project is designed to demonstrate practical implementation of web authentication, database integration, session security, CSRF protection, password hashing, and responsive UI development.

Features
🔐 User Registration & Login
🔑 Secure Password Hashing
🛡️ CSRF Protection
🚫 Login Attempt Lockout
👤 User Session Management
🟢 Live Online Presence
💬 User-to-User Chat
👥 Members List
📊 User Dashboard
🔄 Change Password
🌙 Light/Dark Theme
📱 Responsive Design
🗄️ MySQL Database Integration
❤️ Health Check API
🚪 Secure Logout
🎨 Glassmorphism UI
Tech Stack
Frontend
HTML5
CSS3
JavaScript
Responsive Design
Glassmorphism UI
Backend
Python
Flask
Werkzeug Security
Flask Sessions
Database
MySQL
MySQL Connector/Python
Security
Password Hashing
CSRF Protection
Session Security
Login Lockout
HTTPOnly Cookies
SameSite Cookies
Project Structure
Login page/
│
├── main.py
├── README.md
└── venv/
Requirements
Python 3.10+
MySQL Server
MySQL Workbench (optional)
Web Browser
Installation
1. Clone the Repository
git clone YOUR_GITHUB_REPOSITORY_URL
cd "Login page"
2. Create Virtual Environment
py -m venv venv
3. Activate Virtual Environment

Windows:

venv\Scripts\activate
4. Install Dependencies
pip install flask mysql-connector-python werkzeug
5. Configure MySQL

Make sure MySQL Server is running.

The application uses:

Host: localhost
Port: 3306
User: root
Database: login_app

The application can initialize the required database structure when started.

6. Run the Application
py main.py

Open:

http://127.0.0.1:5000
Demo Accounts

The application includes demo users such as:

Username: bharath
Password: Bharath@123
Username: admin
Password: Admin@123
Username: student
Password: Student@123
Database

The project uses MySQL with the database:

login_app

The main user information is stored in the users table.

The chat functionality uses the message storage table created by the application.

Security Features
Password Hashing

Passwords are stored using secure password hashing rather than storing passwords directly in plain text.

CSRF Protection

CSRF tokens are used to protect important form and API requests from unauthorized cross-site requests.

Login Lockout

Multiple failed login attempts can temporarily lock an account to reduce brute-force login attempts.

Maximum attempts: 5
Lock duration: 60 seconds
Secure Sessions

The application uses secure session settings including:

HTTPOnly cookies
SameSite=Lax
30-minute session lifetime
Main Application Flow
User
  │
  ▼
Registration / Login
  │
  ▼
Flask Backend
  │
  ├── Authentication
  ├── Password Verification
  ├── CSRF Validation
  ├── Session Management
  └── Login Protection
  │
  ▼
MySQL Database
  │
  ▼
Dashboard
  │
  ├── Members
  ├── Online Users
  ├── Chat
  └── Account Settings
API Endpoints
Method	Endpoint	Purpose
GET	/	Login/Home page
POST	/login	Authenticate user
POST	/register	Create account
GET	/dashboard	User dashboard
GET	/health	Application health check
GET	/api/members	Retrieve members
GET	/api/messages	Retrieve messages
POST	/api/messages	Send message
POST	/change-password	Change password
POST	/logout	Logout user
Screens / Modules
Login

Users can securely sign in using their registered username and password.

Registration

New users can create an account with password validation.

Dashboard

After successful authentication, users can access their account dashboard and application features.

Members

Displays registered members and their online presence.

Chat

Authenticated users can communicate through the application's chat functionality.

Change Password

Users can securely update their account password.

Future Improvements
Email verification
Forgot password / password reset
OTP authentication
Google/GitHub OAuth
Admin dashboard
Role-based access control
Profile pictures
Message notifications
WebSocket-based real-time chat
Docker deployment
Cloud database deployment
Production deployment with Gunicorn/Nginx
Author

Bharath M

B.Tech Information Technology
Kongu Engineering College

GitHub: github.com/bharathmurugan

Portfolio: bharath2005.vercel.app

License

This project is created for educational and portfolio purposes.
