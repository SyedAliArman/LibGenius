from flask import Flask, request, jsonify, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# SMTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Supabase
supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)


# Sign up API
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()

    if data["password"] != data["confirm_password"]:
        return jsonify({"message": "Passwords do not match"}), 400

    hashed_password = generate_password_hash(data["password"])

    # Save user
    supabase.table("users").insert({
        "name": data["name"],
        "cms": data["cms"],
        "email": data["email"],
        "password": hashed_password,
        "is_verified": False
    }).execute()

    # Email verification
    token = serializer.dumps(data["email"], salt="email-verify")
    link = url_for("verify_email", token=token, _external=True)

    msg = Message(
        subject="Verify your email",
        sender=app.config["MAIL_USERNAME"],
        recipients=[data["email"]]
    )
    msg.body = f"Click to verify your account:\n{link}"
    mail.send(msg)

    return jsonify({"message": "Signup successful. Check your email"}), 200

# EMAIL VERIFY ROUTE
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, salt="email-verify", max_age=3600)

        supabase.table("users") \
            .update({"is_verified": True}) \
            .eq("email", email) \
            .execute()

        return "Email verified successfully ✅"

    except:
        return "Invalid or expired link ❌"


# Login API
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    user = supabase.table("users") \
        .select("*") \
        .eq("cms", data["cms"]) \
        .execute().data

    if not user:
        return jsonify({"message": "User not found"}), 404

    user = user[0]

    if not user["is_verified"]:
        return jsonify({"message": "Please verify your email"}), 403

    if not check_password_hash(user["password"], data["password"]):
        return jsonify({"message": "Wrong password"}), 401

    return jsonify({"message": "Login successful"}), 200