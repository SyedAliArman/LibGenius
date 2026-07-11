from flask import Flask, request, jsonify, url_for, g, Response
from flask_mail import Mail, Message
import os, uuid, bcrypt, random
from supabase import create_client, Client
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, ValidationError
import threading
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import date
from sentence_transformers import SentenceTransformer
from huggingface_hub import login
from google import genai
from google.genai import types
import PyPDF2
import requests
import io
import traceback
import firebase_admin
from firebase_admin import credentials, messaging
from typing import Optional


# JWT IMPORT
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)


# Model ek baar load hoga server start pe
embedding_model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', token=False)
 
def generate_embedding(text):
    try:
        return embedding_model.encode(text).tolist()
    except Exception as e:
        print(f"Embedding error: {str(e)}")
        return None


load_dotenv()


# HuggingFace warning hatao
os.environ["TOKENIZERS_PARALLELISM"] = "false"
from huggingface_hub import login
if os.getenv("HF_TOKEN"):
    login(token=os.getenv("HF_TOKEN"), add_to_git_credential=False)

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:3000",
                "https://libgenius.netlify.app"
            ]
        }
    },
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "ngrok-skip-browser-warning"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

# ==========================================================
# 1. FIREBASE ADMIN SDK INITIALIZATION
# ==========================================================
try:
    # Direct JSON file se credentials uthao, na env ka dukh na backslash ka rona
    cred = credentials.Certificate("firebase_credentials.json")
    firebase_admin.initialize_app(cred)
    print("Firebase Initialized Successfully!")

except Exception as e:
    print(f"Firebase Initialization Error: {str(e)}")

# ==========================================================
# 2. FIREBASE NOTIFICATION CORE HELPER
# ==========================================================
def send_fcm_notification(fcm_token, title, body):
    """
    Sends a push notification to a specific device token using FCM.
    """
    if not fcm_token:
        print("Notification skipped: FCM Token is missing or empty.")
        return False

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        token=fcm_token,
    )

    try:
        response = messaging.send(message)
        print(f"Push Notification sent successfully: {response}")
        return True
    except Exception as e:
        print(f"FCM messaging payload dispatch failed: {str(e)}")
        return False


# ==========================================================
# 🌟 PYDANTIC BASE MODEL FOR FCM TOKEN
# ==========================================================
class SaveFCMTokenRequest(BaseModel):
    fcm_token: str 

# ==========================================================
# 3. ENDPOINT: FRONTEND SE FCM TOKEN LEKAR SAVE KARNE KE LIYE
# ==========================================================
@app.route("/api/user/save-fcm-token", methods=["POST"])
@jwt_required()
def save_fcm_token():
    user_id = get_jwt_identity()
    
    # 🌟 Input Data ko Validate karein using BaseModel
    try:
        body = SaveFCMTokenRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format. 'fcm_token' is required and must be a string."}), 400

    # Ab aap body.fcm_token se direct data use kar sakte hain
    try:
        # Supabase ke table 'user' mein token update karein
        res = supabase.table("users").update({"fcm_token": body.fcm_token}).eq("cms_id", user_id).execute()
        
        return jsonify({"message": "Device FCM Token synced successfully on backend."}), 200
    except Exception as e:
        return jsonify({"error": f"Database integration failed: {str(e)}"}), 500


# ================================
# SUPABASE CONFRIGURATION
# ================================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

SECRET_KEY = os.getenv("SECRET_KEY")

# ============================
# JWT CONFIGURATION
# =============================
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "fallback-secret-key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)  # Token 24 ghante baad expire hoga
jwt = JWTManager(app)

# =============================
# SMTP CONFRIGURATION
# =============================
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)

def send_email_async(msg):
    with app.app_context():
        try:
            mail.send(msg)
            print(f"Successfully sent email to {msg.recipients}")
        except Exception as e:
            print(f"Failed to send email to {msg.recipients}. Error: {str(e)}")
            import traceback
            traceback.print_exc()


# ===========================================================
# AUTH SYSTEM WITH SIGN UP, VERIFY OTP, RESEND OTP, LOGIN API                  
# ===========================================================
class SignupRequest(BaseModel):
    cms_id: str
    password: str
    fcm_token: Optional[str] = None


class VerifyOTPRequest(BaseModel):
    otp: str

class LoginRequest(BaseModel):
    cms_id: str
    password: str
    fcm_token: Optional[str] = None

# =========================
# 1. SIGN UP                                                                                                            1
# =========================
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        body = SignupRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": "Invalid data format"}), 400
 
    student_check = supabase.table("students").select("*").eq("cms_id", body.cms_id).execute()
    if not student_check.data:
        return jsonify({"error": "CMS not found."}), 404
 
    student = student_check.data[0]
 
    student_email = student.get("email")
    if not student_email:
        return jsonify({"error": "No email found for this CMS in student record"}), 400
 
    user_check = supabase.table("users").select("cms_id").eq("cms_id", body.cms_id).execute()
    if user_check.data:
        return jsonify({"error": "Account already exists for this CMS"}), 400
 
    hashed_pw = bcrypt.hashpw(body.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    otp = str(random.randint(100000, 999999))
 
    # 🔥 Yahan fcm_token automatically insert ho jayega agar request mein aaya toh
    insert_res = supabase.table("users").insert({
        "cms_id": body.cms_id,
        "email": student_email,
        "password_hash": hashed_pw,
        "otp": otp,
        "otp_created_at": datetime.now(timezone.utc).isoformat(),
        "is_verified": False,
        "is_blocked": False,
        "student_name": student.get("student_name"),
        "department": student.get("department"),
        "faculty": student.get("faculty"),
        "semester": student.get("semester"),
        "campus": student.get("campus"),
        "date_of_birth": student.get("date_of_birth"),
        "phone_no": student.get("phone_no"),
        "fcm_token": body.fcm_token  
    }).execute()
 
    try:
        msg = Message(subject="Verification Code",
        recipients=[student_email],
        body=f"Your OTP for App is: {otp}. It will expire in 5 minutes"
        )
        threading.Thread(target=send_email_async, args=(msg,)).start()
        return jsonify({
            "message": "Student found! OTP sent to your email.",
            "student_data": insert_res.data[0] if insert_res.data else None
        }), 201
    except Exception as e:
        return jsonify({"error Failed to send email": str(e)}), 500

# =========================
# 2. VERIFY OTP                                                                                                                2
# =========================
@app.route('/api/verify', methods=['POST'])
def verify():
    body = request.json
    otp = body.get("otp")
 
    if not otp:
        return jsonify({"error": "OTP required"}), 400
 
    res = supabase.table("users").select("*").eq("otp", otp).execute()
 
    if not res.data:
        return jsonify({"error": "Invalid OTP"}), 400
 
    user = res.data[0]
    cms_id = user["cms_id"]
 
    otp_time = datetime.fromisoformat(user["otp_created_at"])
    if otp_time.tzinfo is None:
        otp_time = otp_time.replace(tzinfo=timezone.utc)
 
    if datetime.now(timezone.utc) - otp_time > timedelta(minutes=5):
        return jsonify({"error": "OTP expired"}), 400
 
    supabase.table("users").update({"is_verified": True, "otp": None}).eq("cms_id", cms_id).execute()
 
    # Users table se pura data fetch karo
    user_res = supabase.table("users").select("*").eq("cms_id", cms_id).execute()
    user_data = user_res.data[0] if user_res.data else None
 
    return jsonify({
        "message": "Verification complete! You can now login.",
        "student_data": user_data
    })
# ==========================
# 3. RESEND OTP                                                                                                         3
# ==========================
@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    body = request.json
    cms_id = body.get("cms_id")

    if not cms_id:
        return jsonify({"error": "CMS ID required"}), 400

    res = supabase.table("users").select("*").eq("cms_id", cms_id).execute()

    if not res.data:
        return jsonify({"error": "User not found"}), 404

    user = res.data[0]

    new_otp = str(random.randint(100000, 999999))

    supabase.table("users").update({
        "otp": new_otp,
        "otp_created_at": datetime.now(timezone.utc).isoformat()
    }).eq("cms_id", cms_id).execute()

    msg = Message(
        subject="Your new OTP",
        recipients=[user["email"]],
        body=f"Your new LibGenius verification code is: {new_otp}. It will expire in 5 minutes."
    )

    threading.Thread(target=send_email_async, args=(msg,)).start()

    return jsonify({"message": "New OTP sent to your email!"})

# =========================
# 4. LOGIN (JWT♥)                                                                                                                4
# Flutter yeh token save karega aur baad ki requests mein bhejega
# =========================
@app.route('/api/login', methods=['POST'])
def login():
    try:
        body = LoginRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Missing CMS or Password"}), 400
 
    res = supabase.table("users").select("*").eq("cms_id", body.cms_id).execute()
 
    if not res.data:
        return jsonify({"error": "No account found with this CMS"}), 404
 
    user = res.data[0]
 
    if not user["is_verified"]:
        return jsonify({"error": "Please verify your email first"}), 403
 
    if not bcrypt.checkpw(body.password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        return jsonify({"error": "Incorrect password"}), 401
 
    # 🌟 1. AGAR REQUEST MEIN FCM TOKEN AAYA HAI, TOH DATABASE MEIN SAVE KAREIN
    if body.fcm_token:
        try:
            supabase.table("users").update({"fcm_token": body.fcm_token}).eq("cms_id", body.cms_id).execute()
            # Local variable 'user' ko bhi update kar dete hain taake response mein naya token dikhe
            user["fcm_token"] = body.fcm_token 
        except Exception as e:
            print(f"Error saving FCM token during login: {str(e)}")
            # Isko hum return nahi kar rahe taake token ki wajah se login fail na ho

    access_token = create_access_token(identity=body.cms_id)
 
    return jsonify({
        "message": "Welcome!",
        "access_token": access_token,
        "student_data": user
    })
# ==================================================================================================
# FORGET PASSWORD APIS
# ==================================================================================================

class ForgotPasswordRequest(BaseModel):
    cms_id: str

class VerifyResetOTPRequest(BaseModel):
    otp: str

class ResetPasswordRequest(BaseModel):
    cms_id: str
    new_password: str

# ====================
# 1. FORGET PASSWORD                                                                                                                    5
# ====================
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        body = ForgotPasswordRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400

    # Search user from CMS-ID
    res = supabase.table("users").select("*").eq("cms_id", body.cms_id).execute()

    if not res.data:
        return jsonify({"error": "User not found"}), 404

    user = res.data[0]
    email = user["email"]  

    otp = str(random.randint(100000, 999999))

    supabase.table("users").update({
        "otp": otp,
        "otp_created_at": datetime.now(timezone.utc).isoformat()
    }).eq("cms_id", body.cms_id).execute()  

    msg = Message(
        subject="Password Reset OTP",
        recipients=[email],  
        body=f"Your OTP for forget password is: {otp}. It will expire in 5 minutes"
    )

    threading.Thread(target=send_email_async, args=(msg,)).start()

    return jsonify({"message": f"OTP for your Forgot Password sent to your email"})

# ====================
# 2. VERIFY OTP FOR FORGET PASSWORD                                                                                                 6
# ====================
@app.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    try:
        body = VerifyResetOTPRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400

    res = supabase.table("users").select("*").eq("otp", body.otp).execute()

    if not res.data:
        return jsonify({"error": "Invalid OTP"}), 400

    user = res.data[0]
    cms_id = user["cms_id"]

    otp_time = datetime.fromisoformat(user["otp_created_at"])
    if otp_time.tzinfo is None:
        otp_time = otp_time.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) - otp_time > timedelta(minutes=5):
        return jsonify({"error": "OTP expired"}), 400

    supabase.table("users").update({"otp": None}).eq("cms_id", cms_id).execute()

    return jsonify({
        "message": "OTP verified",
        "cms_id": user["cms_id"]
    })

# =====================
# 3. RESET PASSWORD                                                                                                                        7
# =====================
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        body = ResetPasswordRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400

    hashed_pw = bcrypt.hashpw(body.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    supabase.table("users").update({
        "password_hash": hashed_pw,
        "otp": None
    }).eq("cms_id", body.cms_id).execute()

    return jsonify({"message": "Password reset successful!"})


# =====================================================================================
# CHANGE PASSWORD (LOGGED IN USER)    (JTW♥)                                                                                                 8
# =====================================================================================
class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.route('/api/change-password', methods=['POST'])
@jwt_required()   # This is the decorator this chk the token is valid or not
def change_password():
    try:
        body = ChangePasswordRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400

    # Token se CMS ID nikal rahe hain - Flutter ko CMS ID bhejna nahi padega
    cms_id = get_jwt_identity()

    res = supabase.table("users").select("*").eq("cms_id", cms_id).execute()

    if not res.data:
        return jsonify({"error": "User not found"}), 404

    user = res.data[0]

    if not bcrypt.checkpw(body.current_password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        return jsonify({"error": "Current password is incorrect"}), 401

    hashed_pw = bcrypt.hashpw(body.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    supabase.table("users").update({
        "password_hash": hashed_pw
    }).eq("cms_id", cms_id).execute()

    user_res = supabase.table("users").select("*").eq("cms_id", cms_id).execute()
    user_data = user_res.data[0] if user_res.data else None

    return jsonify({
        "message": "Password changed successfully!",
        "student_data": user_data
        })


# =====================================================================================
# EDIT PROFILE (LOGGED IN USER)  (JWT♥)                                                                                                   9
# =====================================================================================
@app.route('/api/edit-profile', methods=['PUT'])
@jwt_required()
def edit_profile():
    cms_id = get_jwt_identity()
 
    # Check karo user exist karta hai
    check = supabase.table("users").select("cms_id").eq("cms_id", cms_id).execute()
    if not check.data:
        return jsonify({"error": "Student not found"}), 404
 
    update_data = {}
 
    # Text fields form-data se lo
    if request.form.get("student_name"):
        update_data["student_name"] = request.form.get("student_name")
    if request.form.get("department"):
        update_data["department"] = request.form.get("department")
    if request.form.get("faculty"):
        update_data["faculty"] = request.form.get("faculty")
    if request.form.get("semester"):
        update_data["semester"] = request.form.get("semester")
    if request.form.get("campus"):
        update_data["campus"] = request.form.get("campus")
    if request.form.get("phone_no"):
        update_data["phone_no"] = request.form.get("phone_no")
    if request.form.get("date_of_birth"):
        dob = request.form.get("date_of_birth")
        try:
            datetime.strptime(dob, "%Y-%m-%d")
            update_data["date_of_birth"] = dob
        except ValueError:
            return jsonify({"error": "Invalid date format (YYYY-MM-DD required)"}), 400
 
    # Profile picture aayi hai toh upload karo
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        print(f"DEBUG: File received: {file.filename}")
        if file.filename != '':
            allowed_extensions = {'png', 'jpg', 'jpeg'}
            file_ext = file.filename.rsplit('.', 1)[-1].lower()
            print(f"DEBUG: File extension: {file_ext}")
            if file_ext not in allowed_extensions:
                return jsonify({"error": "Only png, jpg, jpeg files allowed"}), 400
            try:
                file_data = file.read()
                # Har user ki ek hi fixed file hogi - extension nahi, sirf cms_id
                # Sari possible extensions delete karo pehle
                for ext in ['jpg', 'jpeg', 'png']:
                    try:
                        supabase.storage.from_("Profile-Pictures").remove([f"{cms_id}.{ext}"])
                    except:
                        pass
                # Naya naam cms_id + extension
                file_name = f"{cms_id}.{file_ext}"
                # Fresh upload karo
                supabase.storage.from_("Profile-Pictures").upload(
                    path=file_name,
                    file=file_data,
                    file_options={"content-type": file.content_type}
                )
                image_url = supabase.storage.from_("Profile-Pictures").get_public_url(file_name)
                update_data["profile_picture_url"] = image_url
            except Exception as e:
                return jsonify({"error": f"Image upload failed: {str(e)}"}), 500
 
    # Kuch update karna hai ya nahi
    if not update_data:
        return jsonify({"error": "No data to update"}), 400
 
    try:
        supabase.table("users").update(update_data).eq("cms_id", cms_id).execute()
        updated_res = supabase.table("users").select("*").eq("cms_id", cms_id).execute()
        return jsonify({
            "message": "Profile updated successfully!",
            "student_data": updated_res.data[0]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===============================================================
# ADMIN AUTH SYSTEM
# ===============================================================

def create_admin():
    email = "libadmin@yopmail.com"
    password = "Naveel123"
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
 
    res = supabase.table("admin").select("*").execute()
    if res.data:
        print("Admin already exists")
        return
 
    res = supabase.table("admin").insert({
        "email": email,
        "hashed_password": hashed_pw
    }).execute()
 
    if res.data:
        print("Admin inserted successfully!")
 
create_admin()
 
 
# =======================================
# LOGIN API ADMIN  (JWT♥)                                                                                                              10
# =======================================
class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    try:
        body = AdminLoginRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": "Invalid data format"}), 400
 
    res = supabase.table("admin").select("*").eq("email", body.email).execute()
    if not res.data:
        return jsonify({"error": "Admin not found"}), 404
 
    admin = res.data[0]
 
    if not bcrypt.checkpw(body.password.encode('utf-8'), admin["hashed_password"].encode('utf-8')):
        return jsonify({"error": "Incorrect password"}), 401
 
    # Admin ka token - email se identify hoga
    access_token = create_access_token(identity=f"admin:{admin['email']}")
 
    return jsonify({
        "message": "Login successful!",
        "access_token": access_token,
        "email": admin["email"]
    })
 
 
# =======================================
# ADMIN CHANGE PASSWORD  (JWT♥)                                                                                                  11
# =======================================
class AdminChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
 

# Kyun: Token se admin ki email niklegi
@app.route("/api/admin/change-password", methods=["POST"])
@jwt_required()
def admin_change_password():
    try:
        body = AdminChangePasswordRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    identity = get_jwt_identity()
 
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    admin_email = identity.replace("admin:", "")
 
    res = supabase.table("admin").select("*").eq("email", admin_email).execute()
    if not res.data:
        return jsonify({"error": "Admin not found"}), 404
 
    admin = res.data[0]
 
    if not bcrypt.checkpw(body.old_password.encode("utf-8"), admin["hashed_password"].encode("utf-8")):
        return jsonify({"error": "Old password is incorrect"}), 401
 
    new_hashed_pw = bcrypt.hashpw(body.new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
 
    supabase.table("admin").update({"hashed_password": new_hashed_pw}).eq("email", admin_email).execute()
 
    return jsonify({"message": "Password changed successfully!"})
 


# ==================================================================================================
# ADMIN FORGET PASSWORD APIS: FORGOT PASSWORD, VERIFY OTP, RESET PASSWORD
# ==================================================================================================
 
class AdminForgotPasswordRequest(BaseModel):
    email: EmailStr
 
class AdminVerifyResetOTPRequest(BaseModel):
    otp: str
 
class AdminResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str
 
# ========================
# 1. ADMIN FORGOT PASSWORD                                                                                                             12
# ========================
@app.route("/api/admin/forgot-password", methods=["POST"])
def admin_forgot_password():
    try:
        body = AdminForgotPasswordRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    res = supabase.table("admin").select("*").eq("email", body.email).execute()
    if not res.data:
        return jsonify({"error": "Admin not found"}), 404
 
    admin = res.data[0]
 
    otp = str(random.randint(100000, 999999))
 
    supabase.table("admin").update({
        "otp": otp,
        "otp_created_at": datetime.now(timezone.utc).isoformat()
    }).eq("email", body.email).execute()
 
    msg = Message(
        subject="Admin Password Reset OTP",
        recipients=[body.email],
        body=f"Your otp for forget password is : {otp}. It will expire in 5 minutes."
    )
    threading.Thread(target=send_email_async, args=(msg,)).start()
 
    return jsonify({"message": "OTP sent to your email"})
 
 
# ====================
# 2. ADMIN VERIFY OTP                                                                                                                       13
# ====================
@app.route("/api/admin/verify-reset-otp", methods=["POST"])
def admin_verify_reset_otp():
    try:
        body = AdminVerifyResetOTPRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    res = supabase.table("admin").select("*").eq("otp", body.otp).execute()
    if not res.data:
        return jsonify({"error": "Invalid OTP"}), 400
 
    admin = res.data[0]
 
    otp_time = datetime.fromisoformat(admin["otp_created_at"])
    if otp_time.tzinfo is None:
        otp_time = otp_time.replace(tzinfo=timezone.utc)
 
    if datetime.now(timezone.utc) - otp_time > timedelta(minutes=5):
        return jsonify({"error": "OTP expired"}), 400
 
    supabase.table("admin").update({"otp": None}).eq("email", admin["email"]).execute()
 
    return jsonify({
        "message": "OTP verified",
        "email": admin["email"]
    })
 
 
# =======================
# 3. ADMIN RESET PASSWORD                                                                                                                      14
# =======================
@app.route("/api/admin/reset-password", methods=["POST"])
def admin_reset_password():
    try:
        body = AdminResetPasswordRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    res = supabase.table("admin").select("*").eq("email", body.email).execute()
    if not res.data:
        return jsonify({"error": "Admin not found"}), 404
 
    hashed_pw = bcrypt.hashpw(body.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
 
    supabase.table("admin").update({
        "hashed_password": hashed_pw,
        "otp": None
    }).eq("email", body.email).execute()
 
    return jsonify({"message": "Password reset successful!"})


# ==================================================================================================
# BOOKS APIs (JWT♥)
# ==================================================================================================
 
# =========================
# GET ALL BOOKS BY (ADMIN and USERS both)                                                                                                                                  15
# =========================
@app.route("/api/get-books", methods=["GET"])
@jwt_required()
def get_all_books():
    res = supabase.table("book").select("*, review(rating_star_number, rating_description, id, users(student_name, user_id, cms_id, email, profile_picture_url)), category(category_name)").execute()
 
    if not res.data:
        return jsonify({"message": "No books found", "books": []}), 200
 
    return jsonify({
        "message": "Books fetched successfully",
        "total": len(res.data),
        "books": res.data
    }), 200

# ================================
# GET BOOK BY ID BY ADMIN  (JWT♥)                                                                                                                   16
# ================================
@app.route("/api/admin/get-books/<int:book_id>", methods=["GET"])
@jwt_required()
def get_book_by_id(book_id):
    identity = get_jwt_identity()
 
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    res = supabase.table("book").select("*").eq("book_id", book_id).execute()
 
    if not res.data:
        return jsonify({"error": "Book not found"}), 404
 
    return jsonify({
        "message": "Book fetched successfully",
        "book":  res.data[0]
    }), 200
 


# =========================
# ADD BOOK  BY ADMIN  (JWT♥)                                                                                                             17
# =========================
@app.route("/api/admin/add-book", methods=["POST"])
@jwt_required()
def add_book():
    identity = get_jwt_identity()
 
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    # Required fields check karo
    required_fields = ["title", "author", "category_id", "isbn", "quantity", "shelf_no"]
    for field in required_fields:
        if not request.form.get(field):
            return jsonify({"error": f"{field} zaroori hai"}), 400
 
    # Check karo same ISBN already exist toh nahi karta
    isbn_check = supabase.table("book").select("isbn").eq("isbn", request.form.get("isbn")).execute()
    if isbn_check.data:
        return jsonify({"error": "Book with this ISBN already exists"}), 400
 
    book_pdf_url = None
    cover_image_url = None
 
    # PDF upload karo
    if "book_pdf" in request.files:
        pdf_file = request.files["book_pdf"]
        if pdf_file.filename != "":
            if not pdf_file.filename.endswith(".pdf"):
                return jsonify({"error": "Sirf PDF file allowed hai"}), 400
            try:
                pdf_name = f"{request.form.get('title')}.pdf"
                supabase.storage.from_("book-pdfs").upload(
                    path=pdf_name,
                    file=pdf_file.read(),
                    file_options={"content-type": "application/pdf", "upsert": "true"}
                )
                book_pdf_url = supabase.storage.from_("book-pdfs").get_public_url(pdf_name)
            except Exception as e:
                return jsonify({"error": f"PDF upload failed: {str(e)}"}), 500
 
    # Cover image upload karo
    if "book_cover" in request.files:
        cover_file = request.files["book_cover"]
        if cover_file.filename != "":
            allowed_ext = {"png", "jpg", "jpeg"}
            file_ext = cover_file.filename.rsplit(".", 1)[-1].lower()
            if file_ext not in allowed_ext:
                return jsonify({"error": "Sirf png, jpg, jpeg allowed hai"}), 400
            try:
                cover_name = f"{request.form.get('title')}.{file_ext}"
                supabase.storage.from_("book-covers").upload(
                    path=cover_name,
                    file=cover_file.read(),
                    file_options={"content-type": cover_file.content_type, "upsert": "true"}
                )
                book_cover_page = supabase.storage.from_("book-covers").get_public_url(cover_name)
            except Exception as e:
                return jsonify({"error": f"Cover image upload failed: {str(e)}"}), 500

    # Embedding banao automatically
    try:
        category_id = request.form.get('category_id', '')

        # Category table alag hai — pehle wahan se category ka naam nikalo
        category_name = ""
        if category_id:
            try:
                cat_res = supabase.table("category").select("category_name").eq("category_id", category_id).single().execute()
                category_name = cat_res.data.get("category_name", "") if cat_res.data else ""
            except Exception:
                category_name = ""

        embed_text = (
            f"Book_id: {request.form.get('book_id', '')} "
            f"Title: {request.form.get('title', '')} "
            f"Author: {request.form.get('author', '')} "
            f"Category: {category_name} "
            f"Description: {request.form.get('description', '')}"
        )
        embedding = generate_embedding(embed_text)
    except Exception:
        embedding = None

    # Extract dynamic fine details from admin form-data (default to 0 if not provided)
    fine_per_day = float(request.form.get("fine_per_day", 0))
 
    # Book insert karo
    res = supabase.table("book").insert({
        "title": request.form.get("title"),
        "author": request.form.get("author"),
        "category_id": int(request.form.get("category_id")),
        "isbn": request.form.get("isbn"),
        "quantity": int(request.form.get("quantity")),
        "shelf_no": request.form.get("shelf_no"),
        "description": request.form.get("description"),
        "publisher_name": request.form.get("publisher_name"),
        "publish_year": request.form.get("publish_year"),
        "language": request.form.get("language"),
        "book_pdf_url": book_pdf_url,
        "book_cover_page": book_cover_page,
        "status": request.form.get("status", "Available"),
        "embedding": embedding,
        "fine_per_day": fine_per_day
    }).execute()
 
    if not res.data:
        return jsonify({"error": "Failed to add book"}), 500

    book_data = res.data[0]

    # PDF chunks background mein process karo
    if book_pdf_url:
        threading.Thread(
            target=process_book_pdf,
            args=(book_data["book_id"], book_pdf_url)
        ).start()
 
    return jsonify({
        "message": "Book added successfully",
        "book": res.data[0]
    }), 201

# =========================
# UPDATE BOOK DETAILS BY ADMIN (JWT♥)
# =========================
class UpdateBookRequest(BaseModel):
    title: str | None = None
    author: str | None = None
    category_id: int | None = None
    isbn: str | None = None
    quantity: int | None = None
    shelf_no: str | None = None
    description: str | None = None
    publisher_year: str | None = None
    language: str | None = None
    status: str | None = None
 
@app.route("/api/admin/books/<int:book_id>", methods=["PUT"])
@jwt_required()
def update_book(book_id):
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    # Book exist check
    book_check = supabase.table("book").select("*").eq("book_id", book_id).execute()
    if not book_check.data:
        return jsonify({"error": "Book not found"}), 404
 
    book = book_check.data[0]
    update_data = {}
 
    # Text fields form-data se lo
    text_fields = ["title", "author", "isbn", "shelf_no", "description", "publisher_year", "language", "status"]
    for field in text_fields:
        if request.form.get(field):
            update_data[field] = request.form.get(field)
 
    if request.form.get("category_id"):
        update_data["category_id"] = int(request.form.get("category_id"))
 
    if request.form.get("quantity"):
        update_data["quantity"] = int(request.form.get("quantity"))

    # Update fine details field dynamically if supplied in request metadata
    if request.form.get("fine_per_day"):
        update_data["fine_per_day"] = float(request.form.get("fine_per_day")) 
 
    # PDF update karo agar aayi hai
    if "book_pdf" in request.files:
        pdf_file = request.files["book_pdf"]
        if pdf_file.filename != "":
            if not pdf_file.filename.endswith(".pdf"):
                return jsonify({"error": "Sirf PDF file allowed hai"}), 400
            try:
                title = request.form.get("title") or book["title"]
                pdf_name = f"{title}.pdf"
                supabase.storage.from_("book-pdfs").upload(
                    path=pdf_name,
                    file=pdf_file.read(),
                    file_options={"content-type": "application/pdf", "upsert": "true"}
                )
                update_data["book_pdf_url"] = supabase.storage.from_("book-pdfs").get_public_url(pdf_name)
            except Exception as e:
                return jsonify({"error": f"PDF upload failed: {str(e)}"}), 500
 
    # Cover image update karo agar aayi hai
    if "book_cover" in request.files:
        cover_file = request.files["book_cover"]
        if cover_file.filename != "":
            allowed_ext = {"png", "jpg", "jpeg"}
            file_ext = cover_file.filename.rsplit(".", 1)[-1].lower()
            if file_ext not in allowed_ext:
                return jsonify({"error": "Sirf png, jpg, jpeg allowed hai"}), 400
            try:
                title = request.form.get("title") or book["title"]
                cover_name = f"{title}.{file_ext}"
                supabase.storage.from_("book-covers").upload(
                    path=cover_name,
                    file=cover_file.read(),
                    file_options={"content-type": cover_file.content_type, "upsert": "true"}
                )
                update_data["book_cover_page"] = supabase.storage.from_("book-covers").get_public_url(cover_name)
            except Exception as e:
                return jsonify({"error": f"Cover image upload failed: {str(e)}"}), 500

    # Embedding banao automatically
    try:
        category_id = request.form.get('category_id', '')

        # Category table alag hai — pehle wahan se category ka naam nikalo
        category_name = ""
        if category_id:
            try:
                cat_res = supabase.table("category").select("category_name").eq("category_id", category_id).single().execute()
                category_name = cat_res.data.get("category_name", "") if cat_res.data else ""
            except Exception:
                category_name = ""

        embed_text = (
            f"Book_id: {request.form.get('book_id', '')} "
            f"Title: {request.form.get('title', '')} "
            f"Author: {request.form.get('author', '')} "
            f"Category: {category_name} "
            f"Description: {request.form.get('description', '')}"
        )
        embedding = generate_embedding(embed_text)
    except Exception:
        embedding = None
 
    if not update_data:
        return jsonify({"error": "No data to update"}), 400
 
    res = supabase.table("book").update(update_data).eq("book_id", book_id).execute()

    book_data = res.data[0]
    # Agar PDF hai toh chunks process karo (agar nayi PDF upload hui hai)
    if book_pdf_url and update_data.get("book_pdf_url") == book_pdf_url:
        threading.Thread(
            target=process_book_pdf,
            args=(book_data["book_id"], book_pdf_url)
        ).start()


    return jsonify({
        "message": "Book updated successfully",
        "book": res.data[0]
    }), 200
 

# =========================
# DELETE BOOK BY ADMIN (by book_id OR title)  (JWT♥)                                                                                        18
# =========================
@app.route("/api/admin/books/delete", methods=["DELETE"])
@jwt_required()
def delete_book():
    identity = get_jwt_identity()
 
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    body = request.json or {}
    book_id = body.get("book_id")
    title = body.get("title")
 
    # Dono mein se ek zaroori hai
    if not book_id and not title:
        return jsonify({"error": "book_id ya title mein se ek zaroori hai"}), 400
 
    # book_id se delete
    if book_id:
        res = supabase.table("book").select("*").eq("book_id", book_id).execute()
        if not res.data:
            return jsonify({"error": "Book not found"}), 404
        supabase.table("book").delete().eq("book_id", book_id).execute()
        return jsonify({
            "message": "Book deleted successfully",
            "deleted_by": "book_id",
            "book_id": book_id
        }), 200
 
    # title se delete
    if title:
        res = supabase.table("book").select("*").ilike("title", title).execute()
        if not res.data:
            return jsonify({"error": "Book not found"}), 404
        # Agar same title ki multiple books hain
        if len(res.data) > 1:
            return jsonify({
                "error": "Multiple books found with this title. Please use book_id to delete.",
                "books": res.data
            }), 400
        supabase.table("book").delete().ilike("title", title).execute()
        return jsonify({
            "message": "Book deleted successfully",
            "deleted_by": "title",
            "title": title
        }), 200


# ==========================================
# GET BOOK PDF URL (USER) (JWT♥)
# Only logged-in users can read the PDF
# ==========================================
@app.route("/api/books/<int:book_id>/pdf/view", methods=["GET"])
@jwt_required()
def view_book_pdf(book_id):
    # 1. Check if the book and its PDF resource exist in database
    book_res = supabase.table("book").select("book_id, title, book_pdf_url").eq("book_id", book_id).execute()
    if not book_res.data:
        return jsonify({"error": "Book record not found"}), 404
        
    pdf_url = book_res.data[0].get("book_pdf_url")
    if not pdf_url:
        return jsonify({"error": "PDF binary source not available for this book"}), 404
        
    try:
        # 2. Stream the file data safely from private/public storage backend
        pdf_stream = requests.get(pdf_url, stream=True)
        
        # 3. Build a pipeline response with target application/pdf headers
        response = Response(
            pdf_stream.iter_content(chunk_size=4096), 
            content_type="application/pdf"
        )
        
        # 🌟 FORCE INLINE INTERPRETATION (Prevents immediate local downloading)
        response.headers["Content-Disposition"] = "inline; filename=protected_document.pdf"
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        return response
        
    except Exception as stream_error:
        print(f"Streaming asset pipeline failed: {str(stream_error)}")
        return jsonify({"error": "Could not establish secure read pipeline for this document."}), 500


# ==================================================================================================
# REVIEW APIs - USER 
# ==================================================================================================
class AddReviewRequest(BaseModel):
    book_id: int | None = None       # book_id se bhi de sakta hai
    title: str | None = None         # title se bhi de sakta hai
    rating_star_number: int
    rating_description: str | None = None


# =========================
# ADD REVIEW   (JWT♥)                                                                                                                     19
# =========================
@app.route("/api/add-reviews", methods=["POST"])
@jwt_required()
def add_review():
    # Token se CMS ID nikalo
    cms_id = get_jwt_identity()
 
    try:
        body = AddReviewRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": "Invalid data format", "details": e.errors()}), 400
 
    # Dono mein se ek zaroori hai
    if not body.book_id and not body.title:
        return jsonify({"error": "Book_id or title is important for give review."}), 400
 
    # Rating is between 1 to 5
    if not 1 <= body.rating_star_number <= 5:
        return jsonify({"error": "Rating must be between 1 and 5"}), 400
 
    # Token se cms_id aaya, us se users table mein se uuid (user_id) nikalo
    user_res = supabase.table("users").select("user_id").eq("cms_id", cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404
    user_id = user_res.data[0]["user_id"]
 
    # book_id resolve karo
    if body.book_id:
        # Direct book_id se check karo
        book_check = supabase.table("book").select("book_id").eq("book_id", body.book_id).execute()
        if not book_check.data:
            return jsonify({"error": "Book not found"}), 404
        final_book_id = body.book_id
 
    else:
        # Title se book dhundo
        book_check = supabase.table("book").select("book_id", "title").ilike("title", body.title).execute()
        if not book_check.data:
            return jsonify({"error": "Book not found with this title"}), 404
        # Agar same title ki multiple books hain
        if len(book_check.data) > 1:
            return jsonify({
                "error": "Multiple books found with this title. Please use book_id instead.",
                "books": book_check.data
            }), 400
        final_book_id = book_check.data[0]["book_id"]
 
    # Check karo user ne pehle se review toh nahi di is book ko
    review_check = supabase.table("review").select("*").eq("book_id", final_book_id).eq("user_id", user_id).execute()
    if review_check.data:
        return jsonify({"error": "You have already reviewed this book"}), 400
 
    # Review save karo
    res = supabase.table("review").insert({
        "book_id": final_book_id,
        "user_id": user_id,
        "rating_star_number": body.rating_star_number,
        "rating_description": body.rating_description,
        "created_at": datetime.now(timezone.utc).isoformat()
    }).execute()
 
    if not res.data:
        return jsonify({"error": "Failed to add review"}), 500
 
    return jsonify({
        "message": "Review added successfully",
        "review": res.data[0]
    }), 201


# =====================================
# GET BOOK REVIEWS BY BOOK ID (View both Users and admin) (JWT♥)                                                                                           20
# ======================================
@app.route("/api/get-reviews/<int:book_id>", methods=["GET"])
@jwt_required()
def get_book_reviews(book_id):
 
    # Check book is exist or not
    book_check = supabase.table("book").select("book_id", "title").eq("book_id", book_id).execute()
    if not book_check.data:
        return jsonify({"error": "Book not found"}), 404
 
    # Fetch Reviews
    res = supabase.table("review").select("*, users(student_name, profile_picture_url)").eq("book_id", book_id).execute()
 
    if not res.data:
        return jsonify({
            "message": "No reviews yet for this book",
            "book_id": book_id,
            "total_reviews": 0,
            "reviews": []
        }), 200
 
    # Calculaye average rating
    total_stars = sum(r["rating_star_number"] for r in res.data)
    avg_rating = round(total_stars / len(res.data), 1)
 
    return jsonify({
        "message": "Reviews fetched successfully",
        "book_id": book_id,
        "book_title": book_check.data[0]["title"],
        "total_reviews": len(res.data),
        "average_rating": avg_rating,
        "reviews": res.data
    }), 200
 

# ==================================================================================================
# ISSUED BOOKS APIs
# ==================================================================================================
 
# =========================
# ISSUE BOOK TO STUDENT (ADMIN) (JWT)
# Rules: Max 4 books per user, book must be available
# =========================
class IssueBookRequest(BaseModel):
    cms_id: str
    book_id: int

@app.route("/api/admin/issue-book", methods=["POST"])
@jwt_required()
def issue_book():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403

    try:
        body = IssueBookRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400

    book_id = body.book_id

    # 1. cms_id se user_id aur fcm_token dono nikalo
    user_check = supabase.table("users").select("user_id", "student_name", "fcm_token").eq("cms_id", body.cms_id).execute()
    if not user_check.data:
        return jsonify({"error": "User not found"}), 404

    user_id = user_check.data[0]["user_id"]
    user_fcm_token = user_check.data[0].get("fcm_token")

    # Check book exists or not
    book_check = supabase.table("book").select("*").eq("book_id", book_id).execute()
    if not book_check.data:
        return jsonify({"error": "Book not found"}), 404

    book = book_check.data[0]
    book_title = book.get("title", "Library Book")

    # Check book is available or not
    if book["quantity"] <= 0 or book["status"].lower() != "available":
        return jsonify({"error": "Book not available"}), 400

    # Check user already have 4 books or not
    issued_check = supabase.table("issued_books").select("issue_id").eq("user_id", user_id).eq("status", "issued").execute()
    if len(issued_check.data) >= 4:
        return jsonify({"error": "Student already has 4 books issued. Return a book first."}), 400

    # Check same book already issued to this user or not
    duplicate_check = supabase.table("issued_books").select("issue_id").eq("user_id", user_id).eq("book_id", book_id).eq("status", "issued").execute()
    if duplicate_check.data:
        return jsonify({"error": "This book is already issued to this student"}), 400

    # Issue the book - due date 14 days later
    issue_date = datetime.now(timezone.utc).date().isoformat()
    due_date = (datetime.now(timezone.utc) + timedelta(days=14)).date().isoformat()

    # 1. Sabse pehle entry insert karo
    res = supabase.table("issued_books").insert({
        "user_id": user_id,
        "cms_id": body.cms_id,
        "book_id": book_id,
        "issue_date": issue_date,
        "due_date": due_date,
        "status": "issued",
        "fine_amount": 0,
        "fine_table_amount": 0  # Initial baseline state
    }).execute()

    new_issue_id = res.data[0]["issue_id"]

    # Decrease book quantity
    new_quantity = book["quantity"] - 1
    new_status = "available" if new_quantity > 0 else "unavailable"
    supabase.table("book").update({
        "quantity": new_quantity,
        "status": new_status
    }).eq("book_id", book_id).execute()

    # 🔍 2. FINE TABLE JOIN & SYNC LOGIC (Jo aap keh rahe ho)
    # Fine table se fine_amount check karo ki kya is issue_id par pehle se koi fine record exist karta hai
    fine_res = supabase.table("fine").select("fine_amount").eq("issue_id", new_issue_id).eq("is_paid", False).execute()
    fine_amount = fine_res.data[0]["fine_amount"] if fine_res.data else 0

    # 🌟 3. REAL-TIME UPDATE BACK TO ISSUED_BOOKS
    # Agar fine_amount zero se zyada milti hai, toh usey 'fine_table_amount' column mein usi waqt save/update karo!
    if fine_amount > 0:
        updated_issue_res = supabase.table("issued_books").update({
            "fine_table_amount": fine_amount
        }).eq("issue_id", new_issue_id).execute()
        
        # Latest updated record return object mein map karne ke liye
        issue_data_to_return = updated_issue_res.data[0]
    else:
        issue_data_to_return = res.data[0]

    # ==========================================================
    # 🌟 AUTOMATIC PUSH NOTIFICATION TRIGGER
    # ==========================================================
    if user_fcm_token:
        notif_title = "Book Issued Successfully! 📚"
        notif_body = f"Hi {user_check.data[0]['student_name']}, '{book_title}' has been issued to your account. Please return it before {due_date}."
        send_fcm_notification(fcm_token=user_fcm_token, title=notif_title, body=notif_body)
    else:
        print(f"Notification skipped: No FCM Token registered for CMS ID {body.cms_id}")
    # ==========================================================

    return jsonify({
        "message": "Book issued successfully",
        "issue": issue_data_to_return, # Isme ab 'fine_table_amount' full updated milega!
        "due_date": due_date,
        "fine_amount": fine_amount
    }), 201

# =========================
# GET CURRENTLY ISSUED BOOKS BY USER (USER) (JWT♥)
# Only logged in user sees own issued books
# =========================
@app.route("/api/my-issued-books", methods=["GET"])
@jwt_required()
def get_my_issued_books():
    cms_id = get_jwt_identity()
 
    user_res = supabase.table("users").select("user_id", "student_name").eq("cms_id", cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404
 
    user_id = user_res.data[0]["user_id"]
 
    # 1. Fetch issued books with fine relationship
    res = supabase.table("issued_books").select("*, book(title, author, shelf_no, book_cover_page, fine_per_day), fine!fine_issue_id_fkey(fine_amount, is_paid, fine_id)").eq("user_id", user_id).eq("status", "issued").execute()
 
    today = date.today()
    issued_books = []
    
    for item in res.data:
        due_date = date.fromisoformat(item["due_date"])
        
        # Live Overdue Fine Calculate karein
        if today > due_date:
            overdue_days = (today - due_date).days
            fine_rate = item.get("book", {}).get("fine_per_day") if item.get("book") else 30
            if fine_rate is None:
                fine_rate = 30
            calculated_fine = overdue_days * fine_rate
        else:
            calculated_fine = 0

        # Fine table se details extract karo (Dynamic check)
        fines_list = item.get("fine") or item.get("fine!fine_issue_id_fkey") or []
        
        extracted_fine_id = None
        is_paid_status = False
        final_fine_table_amount = calculated_fine

        if isinstance(fines_list, list) and len(fines_list) > 0:
            fine_record = fines_list[-1]
            extracted_fine_id = fine_record.get("fine_id")
            db_fine = fine_record.get("fine_amount", 0)
            final_fine_table_amount = db_fine if db_fine > 0 else calculated_fine
            is_paid_status = fine_record.get("is_paid", False)

        # 2. 🔥 JADU: Yahan hum issued_books table ko database mein UPDATE kar rahe hain!
        try:
            supabase.table("issued_books").update({
                "fine_id": extracted_fine_id,
                "fine_table_amount": final_fine_table_amount,
                "fine_amount": calculated_fine
            }).eq("issue_id", item["issue_id"]).execute()
        except Exception as db_err:
            print(f"Database sync failed for issue_id {item['issue_id']}: {str(db_err)}")

        # Local JSON dictionary properties update karein response ke liye
        item["fine_id"] = extracted_fine_id
        item["fine_table_amount"] = final_fine_table_amount
        item["fine_amount"] = calculated_fine
        item["is_paid"] = is_paid_status

        # Nested kachra response se remove karne ke liye
        keys_to_delete = [k for k in item.keys() if "fine" in k and k not in ["fine_amount", "fine_id", "fine_table_amount"]]
        for k in keys_to_delete:
            item.pop(k, None)

        issued_books.append(item)
 
    return jsonify({
        "message": "Issued books fetched and database updated successfully",
        "total": len(issued_books),
        "issued_books": issued_books
    }), 200


# =========================
# GET ALL ISSUED BOOKS WITH STUDENT DETAILS (ADMIN) (JWT♥)
# Admin get all issued books with student details
# =========================
@app.route("/api/admin/issued-books", methods=["GET"])
@jwt_required()
def get_all_issued_books():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    # Fetch data along with relations
    res = supabase.table("issued_books").select("*, users(student_name, cms_id, email, campus, department, faculty, phone_no, date_of_birth, is_blocked, semester, user_id), book(title, author, shelf_no, book_cover_page, fine_per_day), fine!fine_issue_id_fkey(fine_amount, is_paid, fine_id)").eq("status", "issued").execute()

    today = date.today()
    final_output = []
    
    for item in res.data:
        # 1. Live Overdue Fine Calculate karein
        due_date = date.fromisoformat(item["due_date"])
        if today > due_date:
            overdue_days = (today - due_date).days
            fine_rate = item.get("book", {}).get("fine_per_day") if item.get("book") else 30
            if fine_rate is None:
                fine_rate = 30
            calculated_fine = overdue_days * fine_rate
        else:
            calculated_fine = 0
            
        # 2. Dynamic key scanning (Fine table se details nikalne ke liye)
        fines_list = []
        for key in item.keys():
            if "fine" in key and isinstance(item[key], list):
                fines_list = item[key]
                break
        
        extracted_fine_id = None
        is_paid_status = False
        final_fine_table_amount = calculated_fine

        if fines_list and len(fines_list) > 0:
            fine_record = fines_list[-1]  # Latest fine record array se uthao
            extracted_fine_id = fine_record.get("fine_id")
            db_fine = fine_record.get("fine_amount", 0)
            final_fine_table_amount = db_fine if db_fine > 0 else calculated_fine
            is_paid_status = fine_record.get("is_paid", False)

        # 3. 🔥 DATABASE SYNC: Yahan issued_books table permanent update hoga
        try:
            supabase.table("issued_books").update({
                "fine_id": extracted_fine_id,
                "fine_table_amount": final_fine_table_amount,
                "fine_amount": calculated_fine
            }).eq("issue_id", item["issue_id"]).execute()
        except Exception as db_err:
            print(f"Admin API database sync failed for issue_id {item['issue_id']}: {str(db_err)}")

        # Local properties update for JSON response
        item["fine_id"] = extracted_fine_id
        item["fine_table_amount"] = final_fine_table_amount
        item["fine_amount"] = calculated_fine
        item["is_paid"] = is_paid_status

        # 4. CLEANUP: Extra nested kachra clean karne ke liye
        keys_to_delete = [k for k in item.keys() if "fine" in k and k not in ["fine_amount", "fine_id", "fine_table_amount"]]
        for k in keys_to_delete:
            item.pop(k, None)

        final_output.append(item)

    return jsonify({
        "message": "All issued books fetched and database updated successfully",
        "total": len(final_output),
        "issued_books": final_output
    }), 200

    
# =========================
# GET ALL REGISTERED STUDENTS (ADMIN) (JWT♥)
# Admin get all students data
# =========================
@app.route("/api/admin/students", methods=["GET"])
@jwt_required()
def get_all_students():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    res = supabase.table("users").select("user_id, cms_id, student_name, email, department, faculty, semester, campus, date_of_birth, phone_no, profile_picture_url, is_blocked").execute()
 
    return jsonify({
        "message": "Students fetched successfully",
        "total": len(res.data),
        "student_data": res.data
    }), 200

# =========================
# GET ALL FINES (ADMIN) (JWT♥)
# Admin can see all fines
# =========================
@app.route("/api/admin/fines", methods=["GET"])
@jwt_required()
def get_all_fines():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    res = supabase.table("fine").select("*, users(student_name, cms_id, email), issued_books(book_id, due_date)").execute()
 
    return jsonify({
        "message": "Fines fetched successfully",
        "total": len(res.data),
        "fines": res.data
    }), 200


# =========================
# GET MY FINES (USER) (JWT♥)
# User can see their fines
# =========================
@app.route("/api/my-fines", methods=["GET"])
@jwt_required()
def get_my_fines():
    cms_id = get_jwt_identity()
 
    user_res = supabase.table("users").select("user_id").eq("cms_id", cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404
 
    user_id = user_res.data[0]["user_id"]
 
    res = supabase.table("fine").select("*, issued_books(book_id, due_date, book(title))").eq("user_id", user_id).execute()
 
    total_unpaid = sum(f["fine_amount"] for f in res.data if not f["is_paid"])
 
    return jsonify({
        "message": "Fines fetched successfully",
        "total_fines": len(res.data),
        "total_unpaid_amount": total_unpaid,
        "fines": res.data
    }), 200

# =========================
# MARK FINE AS PAID (ADMIN) (JWT♥)
# Admin can mark fine as paid
# =========================
class MarkFinePaidRequest(BaseModel):
    fine_id: int
 
@app.route("/api/admin/mark-fine-paid", methods=["POST"])
@jwt_required()
def mark_fine_paid():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    try:
        body = MarkFinePaidRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    # Check karo fine exist karti hai
    fine_check = supabase.table("fine").select("*").eq("fine_id", body.fine_id).execute()
    if not fine_check.data:
        return jsonify({"error": "Fine not found"}), 404
 
    if fine_check.data[0]["is_paid"]:
        return jsonify({"error": "Fine already paid"}), 400
 
    # Fine paid mark karo
    res = supabase.table("fine").update({
        "is_paid": True,
        "paid_date": datetime.now(timezone.utc).date().isoformat()
    }).eq("fine_id", body.fine_id).execute()
 
    return jsonify({
        "message": "Fine marked as paid successfully",
        "fine": res.data[0]
    }), 200 


# --------------------------------------------------------------------------------------------------
# 5. ADD MANUAL FINE BY CMS_ID (ADMIN ONLY) - Triggered via Web Panel Button
# --------------------------------------------------------------------------------------------------
class AddManualFineRequest(BaseModel):
    cms_id: str                   # user_id ki jagah ab cms_id use hoga
    issue_id: Optional[int] = None 
    fine_amount: float

# --------------------------------------------------------------------------------------------------
# 5. ADD MANUAL FINE BY CMS_ID (ADMIN ONLY) - Duplicate Issue Check Included
# --------------------------------------------------------------------------------------------------
@app.route("/api/admin/add-fine", methods=["POST"])
@jwt_required()
def add_manual_fine():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized! Admin privilege required."}), 403

    try:
        body = AddManualFineRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": "Invalid input format", "details": e.errors()}), 400

    if body.fine_amount <= 0:
        return jsonify({"error": "Fine amount must be greater than zero."}), 400

    try:
        # 🔍 Step 1: Users table se user_id (UUID) nikal lo validation ke liye
        user_res = supabase.table("users").select("user_id").eq("cms_id", body.cms_id).execute()
        
        if not user_res.data:
            return jsonify({"error": f"No student found with CMS ID: {body.cms_id}"}), 404

        real_user_id = user_res.data[0]["user_id"]

        # 🌟 Step 2: DUPLICATE CHECK (Sirf tab jab issue_id provide ki gayi ho)
        if body.issue_id:
            # Check karo ki kya is issue_id par koi aisa fine hai jo abhi tak pay (is_paid = False) nahi hua
            existing_fine = supabase.table("fine")\
                .select("fine_id")\
                .eq("issue_id", body.issue_id)\
                .eq("is_paid", False)\
                .execute()
            
            if existing_fine.data:
                return jsonify({
                    "error": f"An active (unpaid) fine already exists for Issue ID {body.issue_id}. Duplicate entries are not allowed."
                }), 400

        # Fine payload with your newly planned 'cms_id' column
        fine_payload = {
            "user_id": str(real_user_id),       # Table core foreign key (UUID)
            "cms_id": str(body.cms_id),         # Naya column jo aap fine table mein add kar rahe ho
            "issue_id": body.issue_id if body.issue_id else None,
            "return_id": None,
            "fine_amount": body.fine_amount,
            "fine_date": datetime.now(timezone.utc).date().isoformat(),
            "is_paid": False,
            "paid_date": None
        }

        # Insert into Supabase fine table
        res = supabase.table("fine").insert(fine_payload).execute()

        return jsonify({
            "message": f"Fine imposed successfully on Student (CMS ID: {body.cms_id}).",
            "fine": res.data[0]
        }), 201

    except Exception as e:
        return jsonify({"error": f"Failed to execute manual fine tracking: {str(e)}"}), 500


# =========================
# GET ISSUED BOOKS HISTORY (USER) (JWT♥)
# User can see their issued books history
# =========================
@app.route("/api/my-issued-books/history", methods=["GET"])
@jwt_required()
def get_my_issued_history():
    cms_id = get_jwt_identity()
 
    user_res = supabase.table("users").select("user_id").eq("cms_id", cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404
 
    user_id = user_res.data[0]["user_id"]
 
    # Sari history - issued aur returned dono
    # book cover, return_date, fine_amount bhi saath
    res = supabase.table("issued_books").select(
        "*, book(title, author, shelf_no, book_cover_page), return_logs(return_date, fine_id, fine!return_logs_fine_id_fkey(fine_amount, is_paid))"
    ).eq("user_id", user_id).execute()
 
    # return_logs list se nikal ke single object banao
    history = []
    for item in res.data:
        return_logs = item.get("return_logs", [])
        return_info = return_logs[0] if return_logs else None
 
        # return_date issue_date aur due_date ke paas lao
        item["return_date"] = return_info["return_date"] if return_info else None
 
        # fine info alag rakho - agar fine nahi lagi toh 0 bhejo
        fine_data = return_info.get("fine") if return_info else None
        item["fine"] = fine_data if fine_data else {
            "fine_id": None,
            "fine_amount": 0,
            "is_paid": False
        }
 
        del item["return_logs"]
        history.append(item)
 
    return jsonify({
        "message": "History fetched successfully",
        "total": len(history),
        "history": history
    }), 200
 

# =========================
# GET ISSUED BOOKS HISTORY (ADMIN) (JWT♥)
# Admin can see all issued books history
# =========================
@app.route("/api/admin/issued-books/history", methods=["GET"])
@jwt_required()
def get_admin_issued_history():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    res = supabase.table("issued_books").select("*, users(student_name, cms_id, email), book(title, author, shelf_no, book_cover_page), return_logs(return_date, fine!return_logs_fine_id_fkey(fine_amount, is_paid, fine_id))").execute()
 
    history = []
    for item in res.data:
        return_logs = item.get("return_logs", [])
        return_info = return_logs[0] if return_logs else None
 
        # return_date issue_date aur due_date ke paas lao
        item["return_date"] = return_info["return_date"] if return_info else None
 
        # fine info alag rakho - agar fine nahi lagi toh 0 bhejo
        fine_data = return_info.get("fine") if return_info else None
        item["fine"] = fine_data if fine_data else {
            "fine_id": None,
            "fine_amount": 0,
            "is_paid": False
        }
 
        del item["return_logs"]
        history.append(item)


    return jsonify({
        "message": "Full history fetched successfully",
        "total": len(history),
        "history": history
    }), 200


# =========================
# RETURN BOOK VIA QR SCAN (USER) (JWT♥)
# In QR issue_id is applied on book cover , scanned QR will provide issue_id of the book
# Return record is created in return_logs table, and fine is created in fine table if book is late returned
# =========================
class ReturnBookRequest(BaseModel):
    book_id: int
 
@app.route("/api/return-book", methods=["POST"])
@jwt_required()
def return_book():
    cms_id = get_jwt_identity()
 
    try:
        body = ReturnBookRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    book_id = body.book_id
 
    # cms_id se user_id nikalo
    user_res = supabase.table("users").select("user_id").eq("cms_id", cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404
    user_id = user_res.data[0]["user_id"]
 
    # book_id aur user_id se active issue dhundo
    issue_res = supabase.table("issued_books").select("*").eq("book_id", book_id).eq("user_id", user_id).eq("status", "issued").execute()
    if not issue_res.data:
        return jsonify({"error": "No active issue found for this book"}), 404
 
    issue = issue_res.data[0]
    issue_id = issue["issue_id"]
 
    # Late return check karo (Sirf flag lagane ke liye)
    from datetime import date as date_type
    due_date = date_type.fromisoformat(issue["due_date"])
    return_date = datetime.now(timezone.utc)
    is_late = return_date.date() > due_date
 
    # Return record insert karo (fine logging functionality removed from here)
    return_res = supabase.table("return_logs").insert({
        "issue_id": issue_id,
        "book_id": book_id,
        "user_id": user_id,
        "return_date": return_date.date().isoformat(),
        "late_return": is_late,
        "fine_id": None
    }).execute()
 
    return_id = return_res.data[0]["return_id"]
 
    # Issued books status update karo
    supabase.table("issued_books").update({
        "status": "returned"
    }).eq("issue_id", issue_id).execute()
 
    # Book ki quantity wapis barhaao
    book_res = supabase.table("book").select("quantity").eq("book_id", book_id).execute()
    new_quantity = book_res.data[0]["quantity"] + 1
    supabase.table("book").update({
        "quantity": new_quantity,
        "status": "available"
    }).eq("book_id", book_id).execute()
 
    return jsonify({
        "message": "Book returned successfully",
        "cms_id": cms_id,
        "book_id": book_id,
        "return_date": return_date.date().isoformat(),
        "late_return": is_late,
        "return_id": return_id,
        "user_id": user_id,
        "issue_id": issue_id
    }), 200

# =========================
# GET RETURNED BOOKS HISTORY (ADMIN) (JWT♥)
# Admin only can see returned books
# =========================
@app.route("/api/admin/returned-books", methods=["GET"])
@jwt_required()
def get_returned_books():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403
 
    # Get data from return_logs table with joins
    res = supabase.table("return_logs").select("*, users(student_name, cms_id, email), book(title, author), fine!return_logs_fine_id_fkey(fine_amount, is_paid)").execute()
 
    return jsonify({
        "message": "Returned books fetched successfully",
        "total": len(res.data),
        "returned_books": res.data
    }), 200
 
# =========================
# DROP BOOK (ADMIN & USER) (JWT♥)
# Admin: drop book of any user (book_id + user_id)
# User: drop own book (book_id)
# =========================
class DropBookRequest(BaseModel):
    book_id: int
    user_id: str | None = None
 
@app.route("/api/drop-book", methods=["POST"])
@jwt_required()
def drop_book():
    identity = get_jwt_identity()
    is_admin = identity.startswith("admin:")
 
    try:
        body = DropBookRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    # Admin has to send user_id, user has to send book_id
    if is_admin:
        if not body.user_id:
            return jsonify({"error": "Admin ke liye user_id zaroori hai"}), 400
        user_res = supabase.table("users").select("user_id", "student_name", "cms_id", "fcm_token").eq("user_id", body.user_id).execute()
        if not user_res.data:
            return jsonify({"error": "User not found"}), 404
        user = user_res.data[0]
        user_id = user["user_id"]
    else:
        cms_id = identity
        user_res = supabase.table("users").select("user_id", "student_name", "cms_id", "fcm_token").eq("cms_id", cms_id).execute()
        if not user_res.data:
            return jsonify({"error": "User not found"}), 404
        user = user_res.data[0]
        user_id = user["user_id"]
 
    # Check book exists
    book_res = supabase.table("book").select("*").eq("book_id", body.book_id).execute()
    if not book_res.data:
        return jsonify({"error": "Book not found"}), 404
 
    # Active issue
    issue_res = supabase.table("issued_books").select("*").eq("user_id", user_id).eq("book_id", body.book_id).eq("status", "issued").execute()
    if not issue_res.data:
        return jsonify({"error": "No active issue found for this user and book"}), 404
 
    issue = issue_res.data[0]
    issue_id = issue["issue_id"]
    book = book_res.data[0] # Get book info for notification
 
    # Late return check
    from datetime import date as date_type
    due_date = date_type.fromisoformat(issue["due_date"])
    drop_date = datetime.now(timezone.utc)
    is_late = drop_date.date() > due_date
 
    # Insert record in return_logs
    return_res = supabase.table("return_logs").insert({
        "issue_id": issue_id,
        "book_id": body.book_id,
        "user_id": user_id,
        "return_date": drop_date.date().isoformat(),
        "late_return": is_late,
        "fine_id": None
    }).execute()
 
    return_id = return_res.data[0]["return_id"]
 
    # Issued books status update
    supabase.table("issued_books").update({
        "status": "returned"
    }).eq("issue_id", issue_id).execute()
 
    # Book quantity increase
    new_quantity = book["quantity"] + 1
    supabase.table("book").update({
        "quantity": new_quantity,
        "status": "available"
    }).eq("book_id", body.book_id).execute()

    # ==========================================================
    # 🌟 NOTIFICATION: Book Returned Successfully
    # ==========================================================
    if user.get("fcm_token"):
        notif_title = "Book Returned Successfully! 📚"
        notif_body = f"Hi {user['student_name']}, you have successfully returned '{book['title']}'."
        send_fcm_notification(fcm_token=user['fcm_token'], title=notif_title, body=notif_body)
 
    return jsonify({
        "message": "Book dropped successfully",
        "student_name": user["student_name"],
        "cms_id": user["cms_id"],
        "book_id": body.book_id,
        "drop_date": drop_date.date().isoformat(),
        "late_return": is_late,
        "return_id": return_id,
        "category_id": book["category_id"]
    }), 200

# =========================
# Remainder for over due books
# =========================

@app.route("/api/cron/send-due-reminders", methods=["GET"])
def send_due_reminders():
    # 1. Calculate the target date (tomorrow)
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date().isoformat()
    
    try:
        # 2. Fetch records from 'issued_books' where due_date is tomorrow and status is still 'issued'
        due_books = supabase.table("issued_books")\
            .select("user_id, book_id, due_date")\
            .eq("due_date", tomorrow)\
            .eq("status", "issued")\
            .execute()
            
        if not due_books.data:
            return jsonify({"message": "No books are due tomorrow. Notification skipped."}), 200

        sent_count = 0
        
        # 3. Loop through each record and send a notification
        for record in due_books.data:
            user_id = record["user_id"]
            book_id = record["book_id"]
            
            # Retrieve user details (Name, FCM Token) and book title
            user_res = supabase.table("users").select("student_name", "fcm_token").eq("user_id", user_id).execute()
            book_res = supabase.table("book").select("title").eq("book_id", book_id).execute()
            
            if user_res.data and book_res.data:
                user_data = user_res.data[0]
                book_title = book_res.data[0].get("title", "Library Book")
                user_fcm_token = user_data.get("fcm_token")
                student_name = user_data.get("student_name", "Student")
                
                # Check if the user has a valid FCM token
                if user_fcm_token:
                    notif_title = "⚠️ Urgent: Book Due Tomorrow!"
                    # Clearly state that there is only 1 day left before the book becomes overdue
                    notif_body = f"Hi {student_name}, only 1 day remains for your book '{book_title}' before it becomes overdue. Please return it to avoid late fees."
                    
                    # Trigger the Firebase notification
                    send_fcm_notification(fcm_token=user_fcm_token, title=notif_title, body=notif_body)
                    sent_count += 1

        return jsonify({"message": f"Successfully sent {sent_count} overdue warning notifications."}), 200

    except Exception as e:
        print(f"CRON ERROR: {str(e)}")
        return jsonify({"error": f"Failed to process reminders: {str(e)}"}), 500


# =========================
# BLOCK / UNBLOCK USER (ADMIN) (JWT♥)
# =========================
class BlockUnblockRequest(BaseModel):
    cms_id: str
 
# ------------------------------------
# BLOCK USER
# ------------------------------------
@app.route("/api/admin/block-user", methods=["POST"])
@jwt_required()
def block_user():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403

    try:
        body = BlockUnblockRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400

    # Check karo user exist karta hai
    user_res = supabase.table("users").select("user_id", "student_name", "is_blocked").eq("cms_id", body.cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404

    user = user_res.data[0]

    if user["is_blocked"]:
        return jsonify({"error": "User is already blocked"}), 400

    supabase.table("users").update({"is_blocked": True}).eq("cms_id", body.cms_id).execute()

    return jsonify({
        "message": f"{user['student_name']} has been blocked successfully",
        "cms_id": body.cms_id,
        "is_blocked": True
    }), 200


# ------------------------------------
# UNBLOCK USER
# ------------------------------------
@app.route("/api/admin/unblock-user", methods=["POST"])
@jwt_required()
def unblock_user():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403

    try:
        body = BlockUnblockRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400

    # Check karo user exist karta hai
    user_res = supabase.table("users").select("user_id", "student_name", "is_blocked").eq("cms_id", body.cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404

    user = user_res.data[0]

    if not user["is_blocked"]:
        return jsonify({"error": "User is already unblocked"}), 400

    supabase.table("users").update({"is_blocked": False}).eq("cms_id", body.cms_id).execute()

    return jsonify({
        "message": f"{user['student_name']} has been unblocked successfully",
        "cms_id": body.cms_id,
        "is_blocked": False
    }), 200
 
# =========================
# UPDATE FINE (ADMIN) (JWT♥)
# Admin can update fine
# =========================
class UpdateFineRequest(BaseModel):
    fine_id: int
    fine_amount: float

@app.route("/api/admin/update-fine", methods=["PUT"])
@jwt_required()
def update_fine():
    identity = get_jwt_identity()
    if not identity.startswith("admin:"):
        return jsonify({"error": "Unauthorized"}), 403

    try:
        body = UpdateFineRequest(**request.json)
    except ValidationError as e:
        return jsonify({
            "error": "Invalid data format",
            "details": e.errors()
        }), 400

    # Check fine exists
    fine_res = supabase.table("fine").select("*").eq("fine_id", body.fine_id).execute()
    if not fine_res.data:
        return jsonify({"error": "Fine not found"}), 404

    fine_data = fine_res.data[0]

    # Don't allow updating paid fines
    if fine_data["is_paid"]:
        return jsonify({
            "error": "Cannot update an already paid fine"
        }), 400

    # Validate amount
    if body.fine_amount < 0:
        return jsonify({
            "error": "Fine amount cannot be negative"
        }), 400

    # 2. Update Fine Table
    update_res = supabase.table("fine").update({
        "fine_amount": body.fine_amount,
        "fine_date": datetime.now(timezone.utc).date().isoformat()
    }).eq("fine_id", body.fine_id).execute()

    # 3. 🔥 CRITICAL FIX: issued_books table ko bhi usi waqt update karo!
    # Fine record se 'issue_id' uthao jo humne link kiya hua hai
    linked_issue_id = fine_data.get("issue_id")
    if linked_issue_id:
        try:
            supabase.table("issued_books").update({
                "fine_table_amount": body.fine_amount,
                "fine_amount": body.fine_amount
            }).eq("issue_id", linked_issue_id).execute()
        except Exception as sync_err:
            print(f"Syncing to issued_books failed: {str(sync_err)}")

    return jsonify({
        "message": "Fine updated successfully and synced with issued books",
        "fine": update_res.data[0]
    }), 200


 # ==================================================================================================
# PDF CHUNKING HELPER FUNCTIONS
# ==================================================================================================

def extract_text_from_pdf_url(pdf_url):
    """Extract text from PDF URL"""
    try:
        response = requests.get(pdf_url, timeout=30)
        pdf_file = io.BytesIO(response.content)
        reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text
    except Exception as e:
        print(f"PDF extract error: {str(e)}")
        return None

def split_into_chunks(text, chunk_size=500):
    """Split text into chunks"""
    words = text.split()
    chunks = []
    for i in range(0, len(words), chunk_size):
        chunk = " ".join(words[i:i + chunk_size])
        if chunk.strip():
            chunks.append(chunk)
    return chunks


def process_book_pdf(book_id, pdf_url):
    try:
        text = extract_text_from_pdf_url(pdf_url)
        if not text:
            print(f"PDF text not found for book_id: {book_id}")
            return False

        chunks = split_into_chunks(text, chunk_size=500)
        supabase.table("book_chunks").delete().eq("book_id", book_id).execute()

        for index, chunk in enumerate(chunks):
            # 🌟 CLEAN NULL BYTES FROM THE CHUNK TEXT BEFORE PROCESSING
            clean_chunk = chunk.replace('\x00', '').replace('\u0000', '')
            
            # Use clean_chunk instead of chunk for embedding generation
            embedding = generate_embedding(clean_chunk)
            if embedding:
                supabase.table("book_chunks").insert({
                    "book_id": book_id,
                    "chunk_text": clean_chunk,  # 🌟 Insert the cleaned text here
                    "chunk_index": index,
                    "embedding": embedding
                }).execute()
                
        print(f"PDF processing complete for book_id: {book_id}")
        return True
    except Exception as e:
        print(f"PDF processing error: {str(e)}")
        return False


# ==================================================================================================
# NEW HELPER FUNCTION: Contextual Query Condensation
# ==================================================================================================
def condense_query(user_question, conversation_history):
    """
    Rewrites a follow-up question (like 'who is the main character?') into a standalone question 
    (like 'Who is the main character of St. James's Park?') using the history.
    """
    if not conversation_history:
        return user_question

    # Format history into a clean string block for the model
    history_str = ""
    for msg in conversation_history[-5:]: # Look at last 5 turns for context
        role = getattr(msg, 'role', None) or msg.get('role', 'user')
        content = getattr(msg, 'content', None) or msg.get('content', '')
        history_str += f"{role.upper()}: {content}\n"


    condense_prompt = f"""
    Given the following conversation history and a follow-up question, rewrite the follow-up question to be a standalone question that includes all necessary context (like specific book titles, authors, or subjects being discussed). Do not answer the question, just rewrite it into one clear sentence.

    Conversation History:
    {history_str}
    
    Follow-up Question: {user_question}
    Standalone Question:"""

    try:
        # Temporary client just to quickly clean up the query string
        temp_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        response = temp_client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=condense_prompt
        )
        return response.text.strip()
    except Exception as e:
        print(f"Error condensing query: {e}")
        return user_question  # Fallback to original user query if LLM fails

# ==================================================================================================
# CHATBOT API (JWT)
# Flow: Question → Embedding → Supabase search → Groq LLM → Answer
# ==================================================================================================

class ChatbotMessage(BaseModel):
    role: str   
    content: str
 
class ChatbotRequest(BaseModel):
    question: str
    conversation_history: list[ChatbotMessage] = []
 
# =========================
# CHATBOT API (JWT)
# =========================

@app.route("/api/chatbot", methods=["POST"])
@jwt_required()
def chatbot():
    try:
        body = ChatbotRequest(**request.json)
    except ValidationError:
        return jsonify({"error": "Invalid data format"}), 400
 
    question = body.question.strip()
    if not question:
        return jsonify({"error": "Question parameter is missing or blank"}), 400
 
    # Handle catalog aggregation queries
    count_keywords = ["kitni books", "kitni kitabein", "total books", "how many books", "books ki tadad", "library mein kitni", "kitne books"]
    if any(k in question.lower() for k in count_keywords):
        try:
            count_res = supabase.table("book").select("book_id, title, author").execute()
            total_books = len(count_res.data)
            book_titles = [book["title"] for book in count_res.data]
            titles_text = "\n".join([f"{i+1}. {title}" for i, title in enumerate(book_titles)])
            answer = f"Our library currently features a total of {total_books} books:\n\n{titles_text}"
            return jsonify({
                "answer": answer,
                "books_found": count_res.data,
                "total_books": total_books
            }), 200
        except Exception as e:
            return jsonify({"error": f"Count fetch failed: {str(e)}"}), 500
 
    # STEP 1: Condense incoming conversational query
    search_query = condense_query(question, body.conversation_history)
 
    # Generate text vector embeddings for database matching
    question_embedding = generate_embedding(search_query)
    if not question_embedding:
        return jsonify({"error": "Embedding initialization failed"}), 500
 
    # STEP 2 & 3: Match Metadata & Chunks from Supabase with connection retry protections
    similar_books = None
    similar_chunks = None

    try:
        similar_books = supabase.rpc("match_books", {"query_embedding": question_embedding, "match_count": 5}).execute()
    except Exception as db_error:
        print(f"Database book match socket dropped, retrying... Error: {db_error}")
        try:
            similar_books = supabase.rpc("match_books", {"query_embedding": question_embedding, "match_count": 5}).execute()
        except Exception:
            similar_books = None

    try:
        similar_chunks = supabase.rpc("match_chunks", {"query_embedding": question_embedding, "match_count": 5}).execute()
    except Exception as db_error:
        print(f"Database chunk match socket dropped, retrying... Error: {db_error}")
        try:
            similar_chunks = supabase.rpc("match_chunks", {"query_embedding": question_embedding, "match_count": 5}).execute()
        except Exception:
            similar_chunks = None
 
    # STEP 4: Parse context payloads
    books_context = ""
    chunks_context = ""
    books_found = []
 
    # Balanced 0.4 matching threshold to capture deeper context lines like chapters
    if similar_books and similar_books.data:
        for book in similar_books.data:
            if book.get("similarity", 0) > 0.4:
                books_context += f"\nBook: {book.get('title', '')}\nAuthor: {book.get('author', '')}\nDescription: {book.get('description', 'No description available')}\n---"
                books_found.append({
                    "title": book.get("title"),
                    "author": book.get("author"),
                    "similarity": round(book.get("similarity", 0), 2)
                })
 
    if similar_chunks and similar_chunks.data:
        for chunk in similar_chunks.data:
            if chunk.get("similarity", 0) > 0.4:
                chunks_context += f"\nPDF Content excerpt:\n{chunk.get('chunk_text', '')}\n---"
 
    # Safe Fallback: Handle empty vector retrieval scenarios cleanly without throwing an error
    if not books_found and not chunks_context:
        contextual_fallback = "I couldn't find the exact pages or chapter content inside my library database for this request. Please make sure the book PDF is fully indexed or try asking about the summary of the book."
        return jsonify({
            "answer": contextual_fallback,
            "books_found": []
        }), 200
 
    # STEP 5: Compile message strings and process through Gemini 2.5 Flash Lite
    gemini_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    chat_history = []
    
    for msg in body.conversation_history[-10:]:
        chat_history.append(
            types.Content(
                role="user" if msg.role == "user" else "model",
                parts=[types.Part.from_text(text=msg.content)]
            )
        )
 
    system_instruction = """You are a friendly library assistant chatbot named LibGenius.
You must answer user questions using the extracted Library Books details and PDF contents provided.
If the user asks about 'Chapter 1' or specific text details, extract it clearly from the PDF Content Excerpt. 

FORMATTING RULES:
- Always prioritize the structural format requested by the user (e.g., if they ask for points, list items, or a paragraph, follow that layout exactly).
- Keep your total response concise and within a 3-4 line height equivalent, matching the same language as the user."""

    user_prompt_content = f"""Here is the retrieved context from our library system to build your answer:

--- RETRIEVED LIBRARY BOOKS ---
{books_context if books_context else "No matching books cataloged."}
 
--- RETRIEVED PDF CONTENT PARTS ---
{chunks_context if chunks_context else "No PDF parts available."}
 
--- USER QUERY ---
{question}"""
 
    chat_history.append(
        types.Content(role="user", parts=[types.Part.from_text(text=user_prompt_content)])
    )
 
    try:
        response = gemini_client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=chat_history,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.3,
                max_output_tokens=350,
            )
        )
        answer = response.text
    except Exception as llm_error:
        print(f"Gemini API Execution failed: {llm_error}")
        return jsonify({"error": "The generation server is currently busy. Please wait a moment and try again."}), 503
 
    return jsonify({
        "answer": answer,
        "books_found": books_found
    }), 200



# ==================================================
# REMINDER ROUTES
# ==================================================
def trigger_reminders_locally():
    print("⏰ Local Scheduler: Checking for due books...")
    url = "http://127.0.0.1:8000/api/cron/send-due-reminders"
    headers = {"CRON_SECRET_KEY": "d407b301451a238c52b0ba50603b400c8aec321f3b373943"} # Aapki secret key
    
    try:
        # Yeh aapke hi endpoint ko hit karega background mein
        response = requests.get(url, headers=headers)
        print(f"Scheduler Response: {response.json()}")
    except Exception as e:
        print(f"Scheduler failed: {e}")

# Scheduler ko initialize karein aur start karein
scheduler = BackgroundScheduler()

# REAL-WORLD KE LIYE: Roz raat 12 baje chalane ke liye (Isko testing ke baad open karein):
scheduler.add_job(func=trigger_reminders_locally, trigger="cron", hour=0, minute=0)

scheduler.start()    

if __name__ == "__main__":
    app.run(debug=True, port=8000)
