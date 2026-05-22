from flask import Flask, request, jsonify, url_for, g
from flask_mail import Mail, Message
import os, uuid, bcrypt, random
from supabase import create_client, Client
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, ValidationError
import threading
from datetime import datetime, timedelta, timezone
from flask_cors import CORS

# JWT IMPORT
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)


load_dotenv()

app = Flask(__name__)

CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:3000",
            "https://libgenius.netlify.app/"
        ]
    }
})

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
    email: EmailStr
    password: str

class VerifyOTPRequest(BaseModel):
    otp: str

class LoginRequest(BaseModel):
    cms_id: str
    password: str

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
 
 
    user_check = supabase.table("users").select("cms_id").eq("cms_id", body.cms_id).execute()
    if user_check.data:
        return jsonify({"error": "Account already exists for this CMS"}), 400
 
    hashed_pw = bcrypt.hashpw(body.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    otp = str(random.randint(100000, 999999))
 
    # Users table mein insert karo - student ka sara data bhi saath
    insert_res = supabase.table("users").insert({
        "cms_id": body.cms_id,
        "email": body.email,
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
        "phone_no": student.get("phone_no")
    }).execute()
 

    try:
        msg = Message(subject="Verification Code",
        recipients=[body.email],
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
            "student": updated_res.data[0]
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
        "status": request.form.get("status", "Available")
    }).execute()
 
    if not res.data:
        return jsonify({"error": "Failed to add book"}), 500
 
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
 
    if not update_data:
        return jsonify({"error": "No data to update"}), 400
 
    res = supabase.table("book").update(update_data).eq("book_id", book_id).execute()
 
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
    user_id: str
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
 
    user_id = body.user_id
    book_id = body.book_id
 
    # Check user exists or not
    user_check = supabase.table("users").select("user_id", "student_name").eq("user_id", user_id).execute()
    if not user_check.data:
        return jsonify({"error": "User not found"}), 404
 
    # Check book exists or not
    book_check = supabase.table("book").select("*").eq("book_id", book_id).execute()
    if not book_check.data:
        return jsonify({"error": "Book not found"}), 404
 
    book = book_check.data[0]
 
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
 
    res = supabase.table("issued_books").insert({
        "user_id": user_id,
        "book_id": book_id,
        "issue_date": issue_date,
        "due_date": due_date,
        "status": "issued"
    }).execute()
 
    # Decrease book quantity
    new_quantity = book["quantity"] - 1
    new_status = "available" if new_quantity > 0 else "unavailable"
    supabase.table("book").update({
        "quantity": new_quantity,
        "status": new_status
    }).eq("book_id", book_id).execute()
 
    return jsonify({
        "message": "Book issued successfully",
        "issue": res.data[0],
        "due_date": due_date
    }), 201


# =========================
# GET CURRENTLY ISSUED BOOKS BY USER (USER) (JWT♥)
# Only logged in user sees own issued books
# =========================
@app.route("/api/issued-books", methods=["GET"])
@jwt_required()
def get_my_issued_books():
    cms_id = get_jwt_identity()
 
    # cms_id se user_id nikalo
    user_res = supabase.table("users").select("user_id", "student_name").eq("cms_id", cms_id).execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404
 
    user_id = user_res.data[0]["user_id"]
 
    # Sirf currently issued books
    res = supabase.table("issued_books").select("*, book(title, author, shelf_no)").eq("user_id", user_id).eq("status", "issued").execute()
 
    return jsonify({
        "message": "Issued books fetched successfully",
        "total": len(res.data),
        "issued_books": res.data
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
 
    res = supabase.table("issued_books").select("*, users(student_name, cms_id, email, campus, department, faculty, phone_no, date_of_birth, is_blocked, semester, user_id), book(title, author, shelf_no)").eq("status", "issued").execute()
 
    return jsonify({
        "message": "All issued books fetched successfully",
        "total": len(res.data),
        "issued_books": res.data
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
        "*, book(title, author, shelf_no, book_cover_page), return_logs(return_date, fine!return_logs_fine_id_fkey(fine_amount, is_paid, fine_id))"
    ).eq("user_id", user_id).execute()
 
    # return_logs list se nikal ke single object banao
    history = []
    for item in res.data:
        return_logs = item.get("return_logs", [])
        return_info = return_logs[0] if return_logs else None
 
        # return_date issue_date aur due_date ke paas lao
        item["return_date"] = return_info["return_date"] if return_info else None
 
        # fine info alag rakho
        item["fine"] = return_info.get("fine") if return_info else None
 
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
 
        # fine info alag rakho
        item["fine"] = return_info.get("fine") if return_info else None
 
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
    issue_id = issue["issue_id"]  # issue_id ab issue se nikalega
 
    # Late return check karo
    from datetime import date as date_type
    due_date = date_type.fromisoformat(issue["due_date"])
    return_date = datetime.now(timezone.utc)
    is_late = return_date.date() > due_date  # boolean True ya False
 
    # Return record insert karo
    return_res = supabase.table("return_logs").insert({
        "issue_id": issue_id,
        "book_id": book_id,
        "user_id": user_id,
        "return_date": return_date.date().isoformat(),
        "late_return": is_late,
        "fine_id": None
    }).execute()
 
    return_id = return_res.data[0]["return_id"]
    fine_id = None
    fine_amount = 0
 
    # Agar late return hai toh fine create karo
    if is_late:
        overdue_days = (return_date.date() - due_date).days
        fine_amount = overdue_days * 30  # 30 rupees per day
 
        fine_res = supabase.table("fine").insert({
            "user_id": user_id,
            "issue_id": issue_id,
            "return_id": return_id,
            "fine_amount": fine_amount,
            "fine_date": return_date.date().isoformat(),
            "is_paid": False,
            "paid_date": None
        }).execute()
 
        fine_id = fine_res.data[0]["fine_id"]
 
        # Return record mein fine_id link karo
        supabase.table("return_logs").update({
            "fine_id": fine_id
        }).eq("return_id", return_id).execute()
 
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
        "fine_amount": fine_amount,
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
        user_res = supabase.table("users").select("user_id", "student_name", "cms_id").eq("user_id", body.user_id).execute()
        if not user_res.data:
            return jsonify({"error": "User not found"}), 404
        user = user_res.data[0]
        user_id = user["user_id"]
    else:
        # User drop own book using cms_id from token
        cms_id = identity
        user_res = supabase.table("users").select("user_id", "student_name", "cms_id").eq("cms_id", cms_id).execute()
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
    fine_amount = 0
    fine_id = None
 
    # If late then create fine
    if is_late:
        overdue_days = (drop_date.date() - due_date).days
        fine_amount = overdue_days * 30  # 30 rupees per day
 
        fine_res = supabase.table("fine").insert({
            "user_id": user_id,
            "issue_id": issue_id,
            "return_id": return_id,
            "fine_amount": fine_amount,
            "fine_date": drop_date.date().isoformat(),
            "is_paid": False,
            "paid_date": None
        }).execute()
 
        fine_id = fine_res.data[0]["fine_id"]
 
        # Link fine_id in return_logs
        supabase.table("return_logs").update({
            "fine_id": fine_id
        }).eq("return_id", return_id).execute()
 
    # Issued books status update
    supabase.table("issued_books").update({
        "status": "returned"
    }).eq("issue_id", issue_id).execute()
 
    # Book quantity increase
    book = book_res.data[0]
    new_quantity = book["quantity"] + 1
    supabase.table("book").update({
        "quantity": new_quantity,
        "status": "available"
    }).eq("book_id", body.book_id).execute()
 
    return jsonify({
        "message": "Book dropped successfully",
        "student_name": user["student_name"],
        "cms_id": user["cms_id"],
        "book_id": body.book_id,
        "drop_date": drop_date.date().isoformat(),
        "late_return": is_late,
        "fine_amount": fine_amount,
        "return_id": return_id,
        "category_id": book["category_id"]
    }), 200

if __name__ == "__main__":
    app.run(debug=True, port=8000)
