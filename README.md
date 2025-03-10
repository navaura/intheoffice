# Employee Attendance & Notification Portal

A comprehensive web application built with Flask for managing employee attendance, internal communication, and notification systems.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)

## 🌟 Features

### Authentication & User Management
- Role-based access control (Admin/Employee)
- Secure password hashing with Werkzeug
- Self-registration for employees with ID verification
- Location tracking based on IP address

### Attendance System
- Automatic check-in on login
- 8-hour workday tracking with auto-checkout
- Time extension capability
- Attendance history and reporting

### Real-time Notifications
- Web push notifications via pywebpush
- WebSocket integration with Flask-SocketIO
- Support for multiple notification types:
  - Chat messages
  - File sharing
  - Announcements
  - Checkout warnings

### Communication Tools
- Real-time chat between admins and employees
- Announcement broadcasting (global or targeted)
- File sharing and document distribution

## 🚀 Getting Started

### Prerequisites
- Python 3.7+
- SQLite (for development)

### Installation

1. Clone the repository
```bash
git clone https://github.com/navaura/intheoffice.git
cd intheoffice
```

2. Set up a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Set up the database
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Run the application
```bash
python app.py
```

6. Access the application at http://localhost:5000

### Default Admin Credentials
- Username: admin
- Password: admin123

> **Note:** Change these credentials immediately in a production environment!

## 📱 Usage

### Admin Dashboard
As an admin, you can:
- Create and manage employees
- View attendance reports
- Send announcements
- Upload and share files
- Chat with employees

### Employee Dashboard
As an employee, you can:
- Mark attendance automatically on login
- Extend work hours when needed
- View personal attendance history
- Receive notifications
- Chat with administrators
- View shared files and announcements

## 🔒 Security Features

- Password hashing with Werkzeug security
- VAPID key authentication for web push notifications
- IP address tracking for attendance verification
- ID verification for employee registration

## 🛠️ Technical Stack

- **Backend**: Flask, SQLAlchemy
- **Real-time Communication**: Flask-SocketIO, WebSockets
- **Push Notifications**: pywebpush
- **Frontend**: HTML, CSS, JavaScript (with appropriate frameworks)
- **Database**: SQLite (development), can be configured for MySQL/PostgreSQL (production)

## 📂 Project Structure

```
employee-portal/
├── app.py              # Main application file
├── static/             # Static files (CSS, JS)
│   ├── sw.js           # Service Worker for push notifications
│   └── ...
├── templates/          # HTML templates
│   ├── admin_dashboard.html
│   ├── employee_dashboard.html
│   └── ...
├── uploads/            # File upload directory
└── venv/               # Virtual environment
```

## 🔧 Configuration

You can configure the application through environment variables:
- `SECRET_KEY`: Flask secret key
- `DATABASE_URI`: Database connection string
- `VAPID_PRIVATE_KEY` and `VAPID_PUBLIC_KEY`: Keys for web push notifications

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [Flask](https://flask.palletsprojects.com/)
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/)
- [PyWebPush](https://github.com/web-push-libs/pywebpush)
- [SQLAlchemy](https://www.sqlalchemy.org/)
