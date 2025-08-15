# Password Manager Web App

A secure and user-friendly web application for storing and managing your passwords — complete with encryption and two-factor authentication (2FA).  
Built using **Python (Flask)**, **PostgreSQL**, and deployed on **Render**.

---

## Live Demo
**[Click here to view the live app](https://password-manager-web-m8uv.onrender.com/)**

---

## Features

- **Secure Vault** – All stored passwords are encrypted using AES-256.
- **Two-Factor Authentication (2FA)** – Email-based verification before revealing stored passwords.
- **User Accounts** – Register and log in securely with hashed passwords.
- **Master Password** – Used to encrypt/decrypt your personal vault.
- **Add / View / Delete Entries** – Manage accounts, usernames, and passwords.
- **Responsive UI** – Works on desktop and mobile devices.
- **Deployed to the Cloud** – Hosted on Render for easy access anywhere.

---

## Screenshots

### Login Page
![Login Screenshot](assets/login1.png)

### Register Page
![Register Screenshot](assets/register.png)

### Dashboard
![Dashboard Screenshot](assets/dashboard.png)

### Add Entry
![Add Entry Screenshot](assets/add_entry.png)

---

## Tech Stack

- **Backend:** Python (Flask)
- **Database:** PostgreSQL + SQLAlchemy ORM
- **Frontend:** HTML, CSS (custom styling)
- **Security:** AES-256 encryption, `cryptography` library, Flask-WTF for form validation
- **Deployment:** Render (Gunicorn WSGI server)
- **Email Sending:** SMTP (email-validator, smtplib)

---

## Project Structure
```
password-manager-web/
├── app.py # Main Flask app
├── models.py # Database models
├── forms.py # Flask-WTF forms
├── templates/ # HTML templates
├── static/ # CSS, JS, images
├── requirements.txt # Python dependencies
├── Procfile # Render deployment instructions
├── .gitignore
└── README.md
```

