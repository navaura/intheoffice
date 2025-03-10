# app.py - Main Flask Application
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import requests
import uuid
import os
from functools import wraps
from flask_socketio import SocketIO, emit, join_room, leave_room
from pywebpush import webpush, WebPushException
from flask import send_from_directory
import json

VAPID_PRIVATE_KEY = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ2tVNmNoOXdVTkVxc3hJY2cKam9vaWhicWNJVWZ1cGkreWNjVFhPVTVKTXlpaFJBTkNBQVFyUTk5b09uMkxoS2ZvejduSFA2ZlU2cHZldHhaMwpLTC9JeDF2VnlYUlYxSEhGVDdwZXRjKzQvTnZNenZSY2VJdnVURExGMWFSQjYxbFdpTVRkeG1kcQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
VAPID_PUBLIC_KEY = "BCtD32g6fYuEp-jPucc_p9Tqm963Fncov8jHW9XJdFXUccVPul61z7j828zO9Fx4i-5MMsXVpEHrWVaIxN3GZ2o="

VAPID_CLAIMS = {"sub": "mailto:namaskar@navaura.in"}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///office.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20))  # 'admin' or 'employee'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100))
    state = db.Column(db.String(50))  # Derived from location
    department = db.Column(db.String(50), nullable=False)
    designation = db.Column(db.String(50), nullable=False)
    id_type = db.Column(db.String(20))  # 'AADHAR', 'PAN', 'DL'
    id_number = db.Column(db.String(50))
    is_verified = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    check_in = db.Column(db.DateTime, default=datetime.now)
    check_out = db.Column(db.DateTime, nullable=True)
    extended = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(50))

# New models for notification system
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(100))
    message = db.Column(db.Text)
    notification_type = db.Column(db.String(20))  # 'chat', 'file', 'announcement', 'checkout'
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_read = db.Column(db.Boolean, default=False)
    
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_read = db.Column(db.Boolean, default=False)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_global = db.Column(db.Boolean, default=True)  # If false, specific employees

class AnnouncementRecipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    announcement_id = db.Column(db.Integer, db.ForeignKey('announcement.id'))
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    is_read = db.Column(db.Boolean, default=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    filepath = db.Column(db.String(200))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.now)
    description = db.Column(db.Text, nullable=True)
    is_global = db.Column(db.Boolean, default=False)

class FileRecipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    is_notified = db.Column(db.Boolean, default=False)

class PushSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    endpoint = db.Column(db.String(500), unique=True, nullable=False)
    p256dh_key = db.Column(db.String(100), nullable=False)
    auth_key = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_public_ip():
    try:
        return requests.get("https://api64.ipify.org?format=json").json()["ip"]
    except:
        return "Unknown"

# Decorator for admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You need admin privileges to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False  # Reject connection if user is not authenticated

    user_room = f'user_{current_user.id}'
    join_room(user_room)
    print(f"User {current_user.id} joined room {user_room}")

    if current_user.role == 'admin':
        join_room('admin_room')
        print(f"Admin {current_user.id} joined admin_room")
    else:
        employee = Employee.query.filter_by(user_id=current_user.id).first()
        if employee:
            employee_room = f'employee_{employee.id}'
            join_room(employee_room)
            print(f"Employee {current_user.id} joined room {employee_room}")


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')
        if current_user.role == 'admin':
            leave_room('admin_room')
        else:
            employee = Employee.query.filter_by(user_id=current_user.id).first()
            if employee:
                leave_room(f'employee_{employee.id}')

@socketio.on('send_message')
def handle_send_message(data):
    """Handles sending messages via WebSocket"""
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    message = data['message']

    # Save message to database
    chat = ChatMessage(sender_id=sender_id, receiver_id=receiver_id, message=message)
    db.session.add(chat)
    db.session.commit()

    sender = User.query.get(sender_id)
    
    # Emit the message to both sender and receiver
    socketio.emit('receive_message', {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'sender_name': sender.username,
        'message': message
    }, room=f'user_{receiver_id}')

    socketio.emit('receive_message', {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'sender_name': sender.username,
        'message': message
    }, room=f'user_{sender_id}')


# Notification helper functions
def send_notification(user_id, title, message, notification_type):
    """Sends notifications via WebSocket and Web Push API"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        notification_type=notification_type
    )
    db.session.add(notification)
    db.session.commit()

    # Send via WebSocket
    socketio.emit('new_notification', {
        'id': notification.id,
        'title': notification.title,
        'message': notification.message,
        'type': notification.notification_type,
        'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }, room=f'user_{user_id}')

    # Send Web Push Notification
    push_subs = PushSubscription.query.filter_by(user_id=user_id).all()
    for sub in push_subs:
        try:
            webpush(
                subscription_info={
                    "endpoint": sub.endpoint,
                    "keys": {
                        "p256dh": sub.p256dh_key,
                        "auth": sub.auth_key
                    }
                },
                data=json.dumps({
                    "title": title,
                    "message": message
                }),
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=VAPID_CLAIMS
            )
        except WebPushException as ex:
            print("WebPush Error:", ex)


def send_checkout_warning(employee_id):
    """Sends a checkout warning notification to an employee"""
    employee = Employee.query.get(employee_id)
    if employee and employee.user_id:
        send_notification(
            employee.user_id,
            "Auto-Checkout Warning",
            "Your session will automatically check out in 10 minutes. Click to extend.",
            "checkout"
        )

def send_announcement(announcement_id):
    """Sends announcement notifications to recipients"""
    announcement = Announcement.query.get(announcement_id)
    if not announcement:
        return
    
    if announcement.is_global:
        # Send to all employees
        employees = Employee.query.filter(Employee.user_id.isnot(None)).all()
        for employee in employees:
            send_notification(
                employee.user_id,
                f"New Announcement: {announcement.title}",
                announcement.content[:100] + "...",
                "announcement"
            )
            
            # Create recipient record
            recipient = AnnouncementRecipient(
                announcement_id=announcement.id,
                employee_id=employee.id
            )
            db.session.add(recipient)
    else:
        # Send to specific recipients
        recipients = AnnouncementRecipient.query.filter_by(announcement_id=announcement.id).all()
        for recipient in recipients:
            employee = Employee.query.get(recipient.employee_id)
            if employee and employee.user_id:
                send_notification(
                    employee.user_id,
                    f"New Announcement: {announcement.title}",
                    announcement.content[:100] + "...",
                    "announcement"
                )
    
    db.session.commit()

def send_file_notification(file_id, recipient_id=None):
    """Sends file notifications to recipients"""
    file = File.query.get(file_id)
    if not file:
        return
    
    if file.is_global or recipient_id is None:
        # Send to all employees
        employees = Employee.query.filter(Employee.user_id.isnot(None)).all()
        for employee in employees:
            send_notification(
                employee.user_id,
                "New File Available",
                f"A new file '{file.filename}' has been shared with you.",
                "file"
            )
            
            # Create recipient record if it doesn't exist
            recipient = FileRecipient.query.filter_by(file_id=file.id, employee_id=employee.id).first()
            if not recipient:
                recipient = FileRecipient(
                    file_id=file.id,
                    employee_id=employee.id,
                    is_notified=True
                )
                db.session.add(recipient)
    else:
        # Send to specific recipient
        employee = Employee.query.get(recipient_id)
        if employee and employee.user_id:
            send_notification(
                employee.user_id,
                "New File Available",
                f"A new file '{file.filename}' has been shared with you.",
                "file"
            )
            
            # Create recipient record if it doesn't exist
            recipient = FileRecipient.query.filter_by(file_id=file.id, employee_id=employee.id).first()
            if not recipient:
                recipient = FileRecipient(
                    file_id=file.id,
                    employee_id=employee.id,
                    is_notified=True
                )
                db.session.add(recipient)
    
    db.session.commit()

def send_chat_notification(sender_id, receiver_id, message):
    """Creates a chat message and sends notification"""
    chat = ChatMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message=message
    )
    db.session.add(chat)
    db.session.commit()
    
    sender = User.query.get(sender_id)
    send_notification(
        receiver_id,
        f"New message from {sender.username}",
        message[:50] + "..." if len(message) > 50 else message,
        "chat"
    )
    
    return chat

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return render_template('index.html')

@app.route('/sw.js')
def service_worker():
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    data = request.json
    subscription = PushSubscription.query.filter_by(endpoint=data['endpoint']).first()

    if not subscription:
        subscription = PushSubscription(
            user_id=current_user.id,
            endpoint=data['endpoint'],
            p256dh_key=data['keys']['p256dh'],
            auth_key=data['keys']['auth']
        )
        db.session.add(subscription)
        db.session.commit()
    
    return jsonify({"message": "Subscribed successfully!"})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                # Check if user already has attendance today
                employee = Employee.query.filter_by(user_id=user.id).first()
                attendance = Attendance.query.filter_by(employee_id=employee.id).order_by(Attendance.check_in.desc()).first()
                
                if attendance and attendance.check_in.date() == datetime.now().date() and attendance.check_out is None:
                    flash('You are already checked in today!', 'info')
                else:
                    # Create new attendance record
                    new_attendance = Attendance(
                        employee_id=employee.id,
                        ip_address=request.remote_addr
                    )
                    db.session.add(new_attendance)
                    db.session.commit()
                    flash('Attendance marked successfully!', 'success')
                
                return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        id_type = request.form.get('id_type')
        id_number = request.form.get('id_number')
        password = request.form.get('password')

        employee = Employee.query.filter_by(employee_id=employee_id).first()

        if not employee:
            flash('Invalid Employee ID', 'danger')
            return redirect(url_for('register'))

        if employee.is_verified:
            flash('Employee already registered', 'warning')
            return redirect(url_for('login'))

        if employee.id_type != id_type or employee.id_number != id_number:
            flash('ID verification failed', 'danger')
            return redirect(url_for('register'))

        # **Get and Save Location**
        try:
            ip = get_public_ip()
            ip_info = requests.get(f'https://ipinfo.io/{ip}/json').json()

            city = ip_info.get('city', 'Unknown')
            region = ip_info.get('region', 'Unknown')
            country = ip_info.get('country', 'Unknown')

            full_location = f"{city}, {region}, {country}"
        except Exception as e:
            print(f"Location Fetch Error: {e}")
            full_location = "Unknown"

        # Create user
        new_user = User(username=employee_id, role='employee')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Update employee with location
        employee.is_verified = True
        employee.location = full_location
        employee.state = region
        employee.user_id = new_user.id
        db.session.commit()

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    # If employee is logging out, check out automatically
    if current_user.role == 'employee':
        employee = Employee.query.filter_by(user_id=current_user.id).first()
        attendance = Attendance.query.filter_by(employee_id=employee.id).order_by(Attendance.check_in.desc()).first()
        
        if attendance and attendance.check_out is None:
            attendance.check_out = datetime.now()
            db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Admin Routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    employees = Employee.query.all()
    return render_template('admin_dashboard.html', employees=employees)

@app.route('/admin/create_employee', methods=['GET', 'POST'])
@login_required
@admin_required
def create_employee():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        department = request.form.get('department')
        designation = request.form.get('designation')
        id_type = request.form.get('id_type')
        id_number = request.form.get('id_number')

        employee_id = f"EMP{uuid.uuid4().hex[:6].upper()}"

        # Get location from admin's IP
        try:
            ip_info = requests.get(f'https://ipinfo.io/{request.remote_addr}/json').json()
            city = ip_info.get('city', 'Unknown')
            region = ip_info.get('region', 'Unknown')
            country = ip_info.get('country', 'Unknown')
            full_location = f"{city}, {region}, {country}"
        except:
            full_location = "Unknown"

        new_employee = Employee(
            employee_id=employee_id,
            first_name=first_name,
            last_name=last_name,
            department=department,
            designation=designation,
            location=full_location,
            state=region,
            id_type=id_type,
            id_number=id_number
        )

        db.session.add(new_employee)
        db.session.commit()

        flash(f'Employee created successfully. Employee ID: {employee_id}', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_employee.html')


@app.route('/admin/attendance_report')
@login_required
@admin_required
def attendance_report():
    attendances = db.session.query(
        Attendance, Employee
    ).join(
        Employee, Attendance.employee_id == Employee.id
    ).all()
    
    return render_template('attendance_report.html', attendances=attendances)

# New Admin Routes for Notifications
@app.route('/admin/announcements', methods=['GET', 'POST'])
@login_required
@admin_required
def announcements():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_global = 'is_global' in request.form
        recipients = request.form.getlist('recipients') if not is_global else []
        
        announcement = Announcement(
            title=title,
            content=content,
            created_by=current_user.id,
            is_global=is_global
        )
        db.session.add(announcement)
        db.session.commit()
        
        if not is_global and recipients:
            for employee_id in recipients:
                recipient = AnnouncementRecipient(
                    announcement_id=announcement.id,
                    employee_id=employee_id
                )
                db.session.add(recipient)
            db.session.commit()
        
        # Send notifications
        send_announcement(announcement.id)
        
        flash('Announcement created and sent successfully!', 'success')
        return redirect(url_for('announcements'))
    
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    employees = Employee.query.filter_by(is_verified=True).all()
    return render_template('announcements.html', announcements=announcements, employees=employees)

@app.route('/admin/files', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_files():
    if request.method == 'POST':
        # Handle file upload
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        description = request.form.get('description', '')
        is_global = 'is_global' in request.form
        recipients = request.form.getlist('recipients') if not is_global else []
        
        # Save file to disk (you'd need to implement secure file saving)
        filename = f"{uuid.uuid4()}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Create file record
        new_file = File(
            filename=file.filename,
            filepath=filepath,
            uploaded_by=current_user.id,
            description=description,
            is_global=is_global
        )
        db.session.add(new_file)
        db.session.commit()
        
        # Add recipients if not global
        if not is_global and recipients:
            for employee_id in recipients:
                recipient = FileRecipient(
                    file_id=new_file.id,
                    employee_id=employee_id
                )
                db.session.add(recipient)
            db.session.commit()
            
            # Send notifications to specific recipients
            for employee_id in recipients:
                send_file_notification(new_file.id, employee_id)
        else:
            # Send global notification
            send_file_notification(new_file.id)
        
        flash('File uploaded and shared successfully!', 'success')
        return redirect(url_for('manage_files'))
    
    files = File.query.order_by(File.uploaded_at.desc()).all()
    employees = Employee.query.filter_by(is_verified=True).all()
    return render_template('files.html', files=files, employees=employees)

# Employee Routes
@app.route('/employee')
@login_required
def employee_dashboard():
    if current_user.role != 'employee':
        return redirect(url_for('admin_dashboard'))
        
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    
    # Get today's attendance
    today_attendance = Attendance.query.filter_by(employee_id=employee.id).order_by(Attendance.check_in.desc()).first()
    
    # Calculate auto-checkout time
    auto_checkout_time = None
    remaining_time = None
    
    if today_attendance and today_attendance.check_out is None:
        auto_checkout_time = today_attendance.check_in + timedelta(hours=8)
        remaining_time = auto_checkout_time - datetime.now()
        # Convert to minutes
        remaining_time = remaining_time.total_seconds() / 60
        
        # Send warning if less than 10 minutes remaining
        if 0 < remaining_time < 10 and not today_attendance.extended:
            send_checkout_warning(employee.id)
    
    # Get attendance history
    attendance_history = Attendance.query.filter_by(employee_id=employee.id).order_by(Attendance.check_in.desc()).all()
    
    # Get unread notifications count
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    return render_template(
        'employee_dashboard.html', 
        employee=employee, 
        today_attendance=today_attendance,
        auto_checkout_time=auto_checkout_time,
        remaining_time=remaining_time,
        attendance_history=attendance_history,
        unread_notifications=unread_count
    )

@app.route('/employee_chat')
@login_required
def employee_chat():
    return redirect(url_for('chat_dashboard'))

@app.route('/employee/extend_time')
@login_required
def extend_time():
    if current_user.role != 'employee':
        return redirect(url_for('admin_dashboard'))
        
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    attendance = Attendance.query.filter_by(employee_id=employee.id).order_by(Attendance.check_in.desc()).first()
    
    if attendance and attendance.check_out is None:
        # Check if within 10 minutes of auto-checkout (increased from 5)
        auto_checkout_time = attendance.check_in + timedelta(hours=8)
        time_diff = auto_checkout_time - datetime.now()
        
        if time_diff.total_seconds() <= 600:  # 10 minutes in seconds
            attendance.extended = True
            db.session.commit()
            flash('Your work time has been extended.', 'success')
            
            # Send confirmation notification
            send_notification(
                current_user.id,
                "Time Extended",
                "Your work time has been successfully extended.",
                "checkout"
            )
        else:
            flash('You can only extend your time within 10 minutes of auto-checkout.', 'danger')
    else:
        flash('No active attendance found.', 'danger')
        
    return redirect(url_for('employee_dashboard'))

# New routes for notification system
@app.route('/notifications')
@login_required
def view_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/notifications/mark_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    if notification:
        notification.is_read = True
        db.session.commit()
    return redirect(url_for('view_notifications'))

@app.route('/notifications/mark_all_read')
@login_required
def mark_all_notifications_read():
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notification in notifications:
        notification.is_read = True
    db.session.commit()
    return redirect(url_for('view_notifications'))

@app.route('/api/notifications/unread')
@login_required
def get_unread_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
    result = []
    for notification in notifications:
        result.append({
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'type': notification.notification_type,
            'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(result)

# Chat system routes
@app.route('/chat')
@login_required
def chat_dashboard():
    if current_user.role == 'admin':
        employees = Employee.query.filter_by(is_verified=True).all()
        return render_template('admin_chat.html', employees=employees)
    else:
        admins = User.query.filter_by(role='admin').all()
        return render_template('employee_chat.html', admins=admins)

@app.route('/chat/<int:user_id>')
@login_required
def chat_with_user(user_id):
    other_user = User.query.get_or_404(user_id)
    
    # Get chat history
    chats = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user_id)) |
        ((ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == current_user.id))
    ).order_by(ChatMessage.created_at).all()
    
    # Mark received messages as read
    unread_messages = ChatMessage.query.filter_by(
        sender_id=user_id,
        receiver_id=current_user.id,
        is_read=False
    ).all()
    
    for message in unread_messages:
        message.is_read = True
    db.session.commit()
    
    return render_template('chat.html', chats=chats, other_user=other_user)

@app.route('/api/send_message', methods=['POST'])
@login_required
def send_message_api():
    receiver_id = request.json.get('receiver_id')
    message = request.json.get('message')
    
    if not receiver_id or not message:
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
    
    # Create chat message and send notification
    chat = send_chat_notification(current_user.id, receiver_id, message)
    
    return jsonify({
        'status': 'success',
        'chat_id': chat.id,
        'message': message,
        'sent_at': chat.created_at.strftime('%Y-%m-%d %H:%M:%S')
    })

# Auto-checkout function (would be scheduled in a real app)
def auto_checkout():
    with app.app_context():
        current_time = datetime.now()
        # Find all attendance records with no checkout and past 8 hours
        attendances = Attendance.query.filter(
            Attendance.check_out.is_(None),
            Attendance.check_in <= (current_time - timedelta(hours=8)),
            Attendance.extended.is_(False)
        ).all()
        
        for attendance in attendances:
            attendance.check_out = attendance.check_in + timedelta(hours=8)
            db.session.commit()
            
            # Send auto-checkout notification
            employee = Employee.query.get(attendance.employee_id)
            if employee and employee.user_id:
                send_notification(
                    employee.user_id,
                    "Auto-Checkout Completed",
                    "You have been automatically checked out after 8 hours.",
                    "checkout"
                )

# Initialize the app
if __name__ == '__main__':
    # Ensure the upload folder exists
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    
    socketio.run(app, debug=True)
