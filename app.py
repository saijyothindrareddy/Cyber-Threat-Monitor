from flask import Flask, render_template, request, redirect, url_for, send_file, abort
import csv
import os
import requests

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user
from flask_login import logout_user
from flask_login import login_required
from flask_login import current_user

from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from log_parser import parse_logs
from threat_detector import detect_threats
from datetime import datetime
from collections import Counter

app = Flask(__name__)

app.config["SECRET_KEY"] = "soc_dashboard_secret"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

from functools import wraps
from flask import abort

def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if current_user.role != "Admin":
            abort(403)

        return f(*args, **kwargs)

    return decorated_function
def analyst_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if current_user.role not in ["Admin", "Analyst"]:
            abort(403)

        return f(*args, **kwargs)

    return decorated_function

login_manager.login_view = "login"

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)

    role = db.Column(db.String(50), nullable=False)

class Alert(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.String(100))

    ip = db.Column(db.String(100))

    country = db.Column(db.String(100))

    username = db.Column(db.String(100))

    attack_type = db.Column(db.String(100))

    severity = db.Column(db.String(50))

    risk_score = db.Column(db.Integer)

    status = db.Column(db.String(50), default="Open")
    created_at = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):

    return db.session.get(User, int(user_id))

def get_ip_location(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}"
        )

        data = response.json()

        if data["status"] == "success":

            return data["country"]

    except:
        pass

    demo_countries = [
        "United States",
        "India",
        "Germany",
        "China",
        "Russia",
        "United Kingdom",
        "France",
        "Canada"
    ]

    return demo_countries[
        int(ip.split(".")[-1]) % len(demo_countries)
    ]

UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "logs"
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(
    app.config["UPLOAD_FOLDER"],
    exist_ok=True
)

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):

            login_user(user)
            audit = AuditLog(
                username=user.username,
                action="User Logged In",
                timestamp=str(datetime.now())
            )

            db.session.add(audit)
            db.session.commit()

            return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))

# ---------------- DASHBOARD ---------------- #

@app.route("/")
@login_required
def dashboard():

    alerts = Alert.query.all()
    alert_count = Alert.query.count()

    failed_logins = Alert.query.count()

    unique_ips = len(
        set(alert.ip for alert in Alert.query.all())
    )
    open_incidents = Alert.query.filter_by(
        status="Open"
    ).count()

    resolved_incidents = Alert.query.filter_by(
        status="Resolved"
    ).count()
    attacker_counts = {}

    for alert in Alert.query.all():

        if alert.ip not in attacker_counts:
            attacker_counts[alert.ip] = 0

        attacker_counts[alert.ip] += 1

    top_attackers = sorted(
        attacker_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    attacker_labels = [ip for ip, count in top_attackers]

    attacker_values = [count for ip, count in top_attackers]
    country_counts = {}

    for alert in Alert.query.all():

        if alert.country not in country_counts:
            country_counts[alert.country] = 0

        country_counts[alert.country] += 1

    top_countries = sorted(
        country_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    country_labels = [
        country for country, count in top_countries
    ]

    country_values = [
        count for country, count in top_countries
    ]
    # Attack Type Analytics

    attack_counts = {}

    for alert in Alert.query.all():

        attack_type = alert.attack_type

        if attack_type not in attack_counts:
            attack_counts[attack_type] = 0

        attack_counts[attack_type] += 1

    attack_labels = [
        attack for attack, count in attack_counts.items()
    ]

    attack_values = [
        count for attack, count in attack_counts.items()
    ]

    
    return render_template(
        "dashboard.html",
        alerts=alerts,
        alert_count=alert_count,
        failed_logins=failed_logins,
        unique_ips=unique_ips,
        open_incidents=open_incidents,
        resolved_incidents=resolved_incidents,
        attacker_labels=attacker_labels,
        attacker_values=attacker_values,
        country_labels=country_labels,
        country_values=country_values,

        attack_labels=attack_labels,
        attack_values=attack_values
)



#-----------------USERS-------------------------#

@app.route("/users")
@login_required
@admin_required
def users():

    all_users = User.query.all()

    return render_template(
        "users.html",
        users=all_users
    )

@app.route("/add-user", methods=["GET", "POST"])
@login_required
@admin_required
def add_user():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        
        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            return redirect("/users")
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        audit = AuditLog(
            username=current_user.username,
            action=f"Created User {username}",
            timestamp=str(datetime.now())
        )

        db.session.add(audit)
        db.session.commit()

        return redirect("/users")

    return render_template("add_user.html")

@app.route("/delete-user/<int:user_id>")
@login_required
@admin_required
def delete_user(user_id):

    user = User.query.get_or_404(user_id)

    if user.username == "admin":
        return redirect("/users")

    deleted_username = user.username

    db.session.delete(user)
    db.session.commit()

    audit = AuditLog(
        username=current_user.username,
        action=f"Deleted User {deleted_username}",
        timestamp=str(datetime.now())
    )

    db.session.add(audit)
    db.session.commit()

    return redirect("/users")
#----------------Logs-------------------#

class AuditLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100)
    )

    action = db.Column(
        db.String(500)
    )

    timestamp = db.Column(
        db.String(100)
    )

@app.route("/audit-logs")
@login_required
@admin_required
def audit_logs():

    logs = AuditLog.query.order_by(
        AuditLog.id.desc()
    ).all()

    return render_template(
        "audit_logs.html",
        logs=logs
    )

#----------------ATTACK MAP----------------------#
@app.route("/attack-map")
@login_required
def attack_map():

    country_coordinates = {

        "United States":[37.0902,-95.7129],
        "India":[20.5937,78.9629],
        "Germany":[51.1657,10.4515],
        "Russia":[61.5240,105.3188],
        "China":[35.8617,104.1954],
        "Brazil":[-14.2350,-51.9253],
        "United Kingdom":[55.3781,-3.4360],
        "Canada":[56.1304,-106.3468],
        "France":[46.2276,2.2137],
        "Unknown":[0,0]

    }

    attacks = []

    alerts = Alert.query.all()

    for alert in alerts:

        if alert.country in country_coordinates:

            attacks.append({

                "ip": alert.ip,
                "country": alert.country,
                "severity": alert.severity,
                "lat": country_coordinates[alert.country][0],
                "lon": country_coordinates[alert.country][1]

            })

    return render_template(
        "attack_map.html",
        attacks=attacks
    )

# ---------------- UPLOAD LOG FILE ---------------- #

@app.route("/upload", methods=["GET", "POST"])
@login_required
@analyst_required
def upload_logs():

    if request.method == "POST":

        file = request.files["logfile"]

        if file.filename != "":

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            file.save(filepath)
            audit = AuditLog(
                username=current_user.username,
                action=f"Uploaded Log File {file.filename}",
                timestamp=str(datetime.now())
            )

            db.session.add(audit)
            db.session.commit()

            return redirect(url_for("dashboard"))

    files = os.listdir(app.config["UPLOAD_FOLDER"])

    return render_template(
        "upload.html",
        files=files
    )
@app.route("/delete-file/<filename>")
@login_required
@analyst_required
def delete_file(filename):

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    if os.path.exists(filepath):
        os.remove(filepath)

    return redirect(url_for("upload_logs"))
@app.route("/analyze-file/<filename>")
@login_required
@analyst_required
def analyze_file(filename):

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    logs = parse_logs(filepath)

    alerts = detect_threats(logs)

    for alert in alerts:

        existing_alert = Alert.query.filter_by(
            timestamp=alert["timestamp"],
            ip=alert["ip"]
        ).first()

        if not existing_alert:

            new_alert = Alert(
                timestamp=alert["timestamp"],
                ip=alert["ip"],
                country=get_ip_location(alert["ip"]),
                username=alert["user"],
                attack_type=alert["type"],
                severity=alert["severity"],
                risk_score=alert["risk_score"],
                status="Open",
                created_at=alert["timestamp"]
            )

            db.session.add(new_alert)

    db.session.commit()

    return redirect(url_for("dashboard"))


# ---------------- ATTACK LOGS PAGE ---------------- #

@app.route("/logs")
def logs_page():

    alerts = Alert.query.all()

    return render_template("logs.html", alerts=alerts)
# ---------------- INCIDENT MANAGEMENT ---------------- #

@app.route("/incidents")
@login_required
def incidents():

    alerts = Alert.query.order_by(Alert.id.desc()).all()

    return render_template(
        "incidents.html",
        alerts=alerts
    )
@app.route("/resolve/<int:alert_id>")
@login_required
@analyst_required
def resolve_incident(alert_id):

    alert = Alert.query.get_or_404(alert_id)

    alert.status = "Resolved"

    db.session.commit()

    audit = AuditLog(
        username=current_user.username,
        action=f"Resolved Incident INC-{alert.id}",
        timestamp=str(datetime.now())
    )

    db.session.add(audit)
    db.session.commit()

    return redirect(url_for("incidents"))


# ---------------- THREAT INTELLIGENCE ---------------- #

@app.route("/threat-intel")
@login_required
def threat_intelligence():

    return render_template("threat_intel.html")
# ---------------- THREAT HUNTING ---------------- #

@app.route("/threat-hunting")
@login_required
def threat_hunting():

    search = request.args.get("search", "")

    if search:

        alerts = Alert.query.filter(
            (Alert.ip.contains(search)) |
            (Alert.attack_type.contains(search)) |
            (Alert.severity.contains(search)) |
            (Alert.status.contains(search))
        ).all()

    else:

        alerts = Alert.query.order_by(Alert.id.desc()).all()

    return render_template(
        "threat_hunting.html",
        alerts=alerts,
        search=search
    )

# ---------------- NETWORK PAGE ---------------- #

@app.route("/network")
@login_required
def network_activity():

    return render_template("network.html")


# ---------------- SYSTEM HEALTH PAGE ---------------- #

@app.route("/system")
@login_required
def system_health():

    return render_template("system.html")


# ---------------- EXPORT ALERTS ---------------- #

@app.route("/export")
@login_required
def export_alerts():

    alerts = Alert.query.all()

    filename = "alerts_export.csv"

    with open(filename, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "IP Address",
            "User",
            "Attack Type"
        ])

        for alert in alerts:

            writer.writerow([
                alert.timestamp,
                alert.ip,
                alert.username,
                alert.attack_type
            ])

    return send_file(
        filename,
        as_attachment=True
    )
def initialize_database():

    db.create_all()

    admin = User.query.filter_by(
        username="admin"
    ).first()

    if not admin:

        admin = User(
            username="admin",
            password=generate_password_hash("admin123"),
            role="Admin"
        )

        db.session.add(admin)
        db.session.commit()

# ---------------- INITIALIZE DATABASE ---------------- #

with app.app_context():
    initialize_database()


# ---------------- RUN APP ---------------- #

if __name__ == "__main__":

    app.run(debug=True)