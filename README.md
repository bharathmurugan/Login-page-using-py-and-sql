# 🔐 Glassgate Authentication System

A secure and modern authentication web application built using **Python Flask** and **MySQL**.

The application provides user authentication, session management, password protection, login lockout, online presence, member management, dashboard functionality, and chat features through a modern **glassmorphism-based interface**.

---

## 📌 About the Project

**Glassgate Authentication System** is a full-stack web application developed to demonstrate a practical authentication workflow using Flask and MySQL.

The application combines a responsive frontend with a Python Flask backend and MySQL database.

### Project Focus

- Secure user authentication
- User registration
- Password protection
- Session management
- CSRF protection
- Login attempt protection
- Online user presence
- Member management
- Chat functionality
- Responsive user interface
- MySQL database integration

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 User Login | Secure username and password authentication |
| 📝 User Registration | Create a new user account |
| 🔑 Password Security | Password hashing using Werkzeug |
| 🛡️ CSRF Protection | Protects forms and requests from CSRF attacks |
| 🚫 Login Lockout | Temporarily locks login after repeated failed attempts |
| 👤 Session Management | Secure authenticated user sessions |
| 🟢 Online Presence | Shows currently active users |
| 👥 Members | Displays registered application users |
| 💬 Chat | Allows authenticated users to send messages |
| 📊 Dashboard | Central interface for authenticated users |
| 🔄 Change Password | Allows users to update their password |
| 🌙 Theme Toggle | Supports light and dark themes |
| 📱 Responsive UI | Works across different screen sizes |
| 🗄️ MySQL | Persistent database storage |
| ❤️ Health Check | Application health monitoring endpoint |
| 🚪 Logout | Securely terminates the user session |

---

## 🛠️ Technologies Used

### Frontend

- HTML5
- CSS3
- JavaScript
- Responsive Web Design
- Glassmorphism UI

### Backend

- Python
- Flask
- Werkzeug
- Flask Sessions

### Database

- MySQL
- MySQL Connector/Python

### Security

- Password Hashing
- CSRF Protection
- Session Security
- Login Attempt Lockout
- HTTPOnly Cookies
- SameSite Cookies

---

## 📂 Project Structure

```text
Glassgate-Authentication-System/
│
├── main.py
├── README.md
└── requirements.txt
```
The main application is implemented in main.py, which contains the Flask backend and web interface.

⚙️ Requirements
Software Requirements

Before running the project, install the following:

Python 3.10 or higher
MySQL Server
MySQL Workbench (optional)
Git
Modern Web Browser

Python Packages

The project requires the following Python packages:

Flask
mysql-connector-python
Werkzeug

Python Packages

The project requires the following Python packages:

Flask
mysql-connector-python
Werkzeug

🚀 Installation
1. Clone the Repository
git clone YOUR_GITHUB_REPOSITORY_URL

Navigate into the project directory:

cd Glassgate-Authentication-System

2. Create a Virtual Environment

For Windows:

py -m venv venv

3. Activate the Virtual Environment
venv\Scripts\activate

4. Install Dependencies
pip install -r requirements.txt

🗄️ MySQL Configuration

Make sure your MySQL Server is running before starting the application.

The application uses the following default configuration:

Setting	Value
Host	localhost
Port	3306
Username	root
Database	login_app

Database Name
login_app

The application can initialize the required database structure when it starts.

▶️ Run the Application

Start the Flask application:

py main.py

After the server starts, open the following URL in your browser:

http://127.0.0.1:5000

🔑 Demo Login Credentials
User 1
Username : bharath
Password : Bharath@123
User 2
Username : admin
Password : Admin@123
User 3
Username : student
Password : Student@123

Note: For production deployment, replace demo credentials and use environment variables for sensitive configuration.

🔒 Security Implementation
🔑 Password Hashing

User passwords are protected using secure password hashing instead of storing passwords directly in plain text.

🛡️ CSRF Protection

CSRF tokens are used to protect important forms and requests from unauthorized cross-site requests.

🚫 Login Attempt Protection

The application limits repeated failed login attempts.

Security Setting	Value
Maximum Attempts	5
Lock Duration	60 seconds

This helps reduce brute-force login attempts.

🍪 Secure Sessions

The application uses secure session settings:

Setting	Value
HTTPOnly Cookies	Enabled
SameSite	Lax
Session Lifetime	30 minutes

📊 Application Workflow

                             ┌─────────────────┐
                         │      User       │
                         └────────┬────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   Login / Registration  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │     Flask Backend       │
                    └────────────┬────────────┘
                                 │
             ┌───────────────────┼───────────────────┐
             │                   │                   │
             ▼                   ▼                   ▼
      Authentication       CSRF Protection    Session Management
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      MySQL Database     │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │       Dashboard         │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
          Members              Chat          Account Settings

🌐 API Endpoints
Method	Endpoint	Purpose
GET	/	Login / Home page
POST	/login	Authenticate user
POST	/register	Register a new user
GET	/dashboard	Open user dashboard
GET	/health	Check application health
GET	/api/members	Retrieve members
GET	/api/messages	Retrieve messages
POST	/api/messages	Send a message
POST	/change-password	Change user password
POST	/logout	Logout user

🎯 Project Objectives
Build a secure authentication system using Flask.
Connect a web application with MySQL.
Implement password hashing and verification.
Implement session-based authentication.
Protect requests using CSRF tokens.
Implement login attempt protection.
Build a responsive glassmorphism interface.
Provide member, presence, and chat functionality.

📚 Learning Outcomes

This project demonstrates practical knowledge of:

Python Flask
MySQL Database Integration
REST API Development
CRUD Operations
User Authentication
Password Hashing
Session Management
CSRF Protection
Web Security
HTML, CSS and JavaScript
Responsive Web Design

👨‍💻 Author
Bharath M

B.Tech Information Technology
Kongu Engineering College

GitHub: github.com/bharathmurugan
Portfolio: bharath2005.vercel.app

📄 License

This project is developed for educational and portfolio purposes.
