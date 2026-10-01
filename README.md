# 🔐 Glassgate Authentication System

A secure and modern authentication web application built using **Python Flask** and **MySQL**, featuring user authentication, session management, password protection, login lockout, online presence, member management, and chat functionality.

---

## 📌 About the Project

**Glassgate Authentication System** is a full-stack web application developed to demonstrate a practical and secure authentication workflow.

The application provides users with a modern **glassmorphism-based interface** while handling authentication and user data through a Flask backend connected to a MySQL database.

The project focuses on:

- Secure user authentication
- Password protection
- Session management
- CSRF protection
- Login attempt protection
- User presence
- Member management
- Chat functionality
- Responsive user interface

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 User Login | Secure username and password authentication |
| 📝 User Registration | Create a new user account |
| 🔑 Password Security | Password hashing using Werkzeug |
| 🛡️ CSRF Protection | Protects forms and requests from CSRF attacks |
| 🚫 Login Lockout | Temporarily locks login after repeated failures |
| 👤 Session Management | Secure authenticated user sessions |
| 🟢 Online Presence | Shows currently active users |
| 👥 Members | Displays registered application users |
| 💬 Chat | Allows authenticated users to send messages |
| 📊 Dashboard | Central interface for authenticated users |
| 🔄 Change Password | Allows users to update their password |
| 🌙 Theme Toggle | Light/dark interface support |
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
```
The project is primarily implemented in main.py, including the Flask backend and web interface.

⚙️ Requirements

Before running the project, install:

Python 3.10 or higher
MySQL Server
MySQL Workbench (optional)
Git
Modern web browser

🚀 Installation
1. Clone the Repository
git clone YOUR_GITHUB_REPOSITORY_URL

Navigate into the project:

cd Glassgate-Authentication-System
2. Create a Virtual Environment

Windows:

py -m venv venv
3. Activate the Virtual Environment
venv\Scripts\activate
4. Install Required Packages
pip install flask mysql-connector-python werkzeug
🗄️ MySQL Configuration

Make sure your MySQL Server is running.

The application uses the following default configuration:

Host      : localhost
Port      : 3306
Username  : root
Database  : login_app

The application can initialize the required database structure when it starts.

Database Name
login_app
▶️ Run the Application

Start the Flask application:

py main.py

After the server starts, open:

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

For production deployment, replace demo credentials and use environment variables for sensitive configuration.

🔒 Security Implementation
Password Hashing

User passwords are protected using secure password hashing instead of storing passwords directly in plain text.

CSRF Protection

CSRF tokens are used to protect important forms and requests from unauthorized cross-site requests.

Login Attempt Protection

The application limits repeated failed login attempts.

Maximum Attempts : 5
Lock Duration    : 60 seconds

This helps reduce brute-force login attempts.
