import os
import json
import hashlib
import time

from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    request,
    jsonify
)

from werkzeug.utils import secure_filename

import firebase_admin
from firebase_admin import credentials, auth, db


# ============================================
# APPLICATION CONFIGURATION
# ============================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-before-production"
)

MAX_UPLOAD_MB = int(
    os.environ.get("MAX_UPLOAD_MB", "100")
)

app.config["MAX_CONTENT_LENGTH"] = (
    MAX_UPLOAD_MB * 1024 * 1024
)

PROJECT_ID = os.environ.get(
    "FIREBASE_PROJECT_ID",
    "forensic-lab-7e02c"
)

DATABASE_URL = os.environ.get(
    "FIREBASE_DATABASE_URL",
    "https://forensic-lab-7e02c-default-rtdb.firebaseio.com/"
)

ADMIN_UID = os.environ.get("ADMIN_UID")

firebase_ready = False


# ============================================
# FIREBASE ADMIN INITIALIZATION
# ============================================

def initialize_firebase():

    global firebase_ready

    if firebase_ready:
        return True

    service_account_json = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_JSON"
    )

    if not service_account_json:
        app.logger.error(
            "FIREBASE_SERVICE_ACCOUNT_JSON is missing."
        )
        return False

    try:
        service_account = json.loads(service_account_json)

        credential = credentials.Certificate(service_account)

        if not firebase_admin._apps:
            firebase_admin.initialize_app(
                credential,
                {
                    "databaseURL": DATABASE_URL,
                    "projectId": PROJECT_ID
                }
            )

        firebase_ready = True

        return True

    except Exception:
        app.logger.exception(
            "Firebase initialization failed."
        )

        return False


def database_ready():
    return initialize_firebase()


# ============================================
# DATABASE HELPERS
# ============================================

def user_reference(uid):
    return db.reference(f"users/{uid}")


def get_user(uid):
    return user_reference(uid).get() or {}


def save_user(uid, data):
    user_reference(uid).update(data)


def current_time():
    return int(time.time() * 1000)


# ============================================
# AUTHENTICATION HELPERS
# ============================================

def get_token_user():

    if not database_ready():
        raise RuntimeError("Firebase is not configured.")

    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        raise PermissionError("Authentication required.")

    token = header.split(" ", 1)[1].strip()

    if not token:
        raise PermissionError("Invalid authentication token.")

    decoded_token = auth.verify_id_token(token)

    return decoded_token


def require_auth(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        try:
            decoded = get_token_user()

            uid = decoded["uid"]
            user = get_user(uid)

            if user.get("suspended", False):
                return jsonify({
                    "error": "Your account has been suspended."
                }), 403

            request.current_user = decoded

            return function(*args, **kwargs)

        except PermissionError as error:
            return jsonify({"error": str(error)}), 401

        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503

        except Exception:
            return jsonify({
                "error": "Authentication failed."
            }), 401

    return wrapper


def require_admin(function):

    @wraps(function)
    @require_auth
    def wrapper(*args, **kwargs):

        uid = request.current_user["uid"]

        if not ADMIN_UID:
            return jsonify({
                "error": "Administrator configuration is missing."
            }), 503

        if uid != ADMIN_UID:
            return jsonify({
                "error": "Administrator access required."
            }), 403

        return function(*args, **kwargs)

    return wrapper


# ============================================
# PUBLIC WEBSITE PAGES
# ============================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/auth")
def authentication():
    return render_template("auth.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/analyze")
def analyze():
    return render_template("analyze.html")


@app.route("/admin")
def admin():
    return render_template("admin.html")


# ============================================
# USER SYNCHRONIZATION
# ============================================

@app.route("/api/sync-user", methods=["POST"])
@require_auth
def sync_user():

    decoded = request.current_user

    uid = decoded["uid"]
    email = decoded.get("email", "")

    body = request.get_json(silent=True) or {}

    name = (
        body.get("name")
        or decoded.get("name")
        or email.split("@")[0]
    )

    reference = user_reference(uid)

    existing = reference.get() or {}

    now = current_time()

    if not existing:

        reference.set({
            "uid": uid,
            "name": name,
            "email": email,
            "created_at": now,
            "last_seen": now,
            "suspended": False
        })

    else:

        reference.update({
            "email": email,
            "last_seen": now
        })

        if name and not existing.get("name"):
            reference.update({"name": name})

    return jsonify({
        "success": True,
        "uid": uid
    })


# ============================================
# CURRENT USER
# ============================================

@app.route("/api/me")
@require_auth
def me():

    uid = request.current_user["uid"]
    user = get_user(uid)

    return jsonify({
        "uid": uid,
        "email": request.current_user.get("email"),
        "name": user.get("name"),
        "admin": uid == ADMIN_UID
    })


# ============================================
# USER ACTIVITY
# ============================================

@app.route("/api/activity", methods=["POST"])
@require_auth
def activity():

    uid = request.current_user["uid"]

    save_user(uid, {
        "last_seen": current_time()
    })

    return jsonify({"success": True})


# ============================================
# FILE ANALYSIS - SHA256 MVP
# ============================================

@app.route("/api/analyze", methods=["POST"])
@require_auth
def analyze_file():

    if "file" not in request.files:
        return jsonify({
            "error": "No file was uploaded."
        }), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({
            "error": "Please select a file."
        }), 400

    filename = secure_filename(uploaded_file.filename)

    if not filename:
        return jsonify({
            "error": "Invalid filename."
        }), 400

    sha256 = hashlib.sha256()
    file_size = 0

    try:

        while True:

            chunk = uploaded_file.stream.read(1024 * 1024)

            if not chunk:
                break

            file_size += len(chunk)

            sha256.update(chunk)

        file_hash = sha256.hexdigest()

        uid = request.current_user["uid"]

        history_reference = db.reference(
            f"history/{uid}"
        ).push()

        record = {
            "filename": filename,
            "size": file_size,
            "sha256": file_hash,
            "created_at": current_time(),
            "analysis_type": "SHA-256"
        }

        history_reference.set(record)

        return jsonify({
            "success": True,
            "filename": filename,
            "size": file_size,
            "sha256": file_hash,
            "message": (
                "SHA-256 fingerprint generated successfully. "
                "No authenticity conclusion is made."
            )
        })

    except Exception:

        app.logger.exception("File analysis failed.")

        return jsonify({
            "error": "File analysis failed."
        }), 500


# ============================================
# USER ANALYSIS HISTORY
# ============================================

@app.route("/api/history")
@require_auth
def history():

    uid = request.current_user["uid"]

    records = db.reference(
        f"history/{uid}"
    ).get() or {}

    history_items = []

    for record_id, record in records.items():

        record["id"] = record_id

        history_items.append(record)

    history_items.sort(
        key=lambda item: item.get("created_at", 0),
        reverse=True
    )

    return jsonify({
        "history": history_items
    })


# ============================================
# PUBLIC ACTIVE ADVERTISEMENTS
# ============================================

@app.route("/api/ads")
@require_auth
def public_ads():

    records = db.reference("ads").get() or {}

    active_ads = []

    for ad_id, ad in records.items():

        if ad.get("active"):

            active_ads.append({
                "id": ad_id,
                "title": ad.get("title", ""),
                "text": ad.get("text", ""),
                "url": ad.get("url", "")
            })

    return jsonify({
        "ads": active_ads
    })


# ============================================
# ADMIN STATISTICS
# ============================================

@app.route("/api/admin/stats")
@require_admin
def admin_stats():

    users = db.reference("users").get() or {}
    ads = db.reference("ads").get() or {}

    now = current_time()

    five_minutes = 5 * 60 * 1000
    seven_days = 7 * 24 * 60 * 60 * 1000

    online_users = 0
    weekly_users = 0
    active_ads = 0

    for user in users.values():

        last_seen = user.get("last_seen", 0)
        created_at = user.get("created_at", 0)

        if now - last_seen <= five_minutes:
            online_users += 1

        if now - created_at <= seven_days:
            weekly_users += 1

    for ad in ads.values():

        if ad.get("active"):
            active_ads += 1

    return jsonify({
        "total_users": len(users),
        "online_users": online_users,
        "weekly_users": weekly_users,
        "active_ads": active_ads
    })


# ============================================
# ADMIN USER MANAGEMENT
# ============================================

@app.route("/api/admin/users")
@require_admin
def admin_users():

    users = db.reference("users").get() or {}

    result = []

    for uid, user in users.items():

        result.append({
            "uid": uid,
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "suspended": user.get("suspended", False),
            "created_at": user.get("created_at", 0),
            "last_seen": user.get("last_seen", 0)
        })

    result.sort(
        key=lambda item: item.get("created_at", 0),
        reverse=True
    )

    return jsonify({
        "users": result
    })


@app.route(
    "/api/admin/user/<uid>/suspend",
    methods=["POST"]
)
@require_admin
def suspend_user(uid):

    if uid == ADMIN_UID:
        return jsonify({
            "error": "You cannot suspend the main administrator."
        }), 400

    reference = user_reference(uid)

    user = reference.get()

    if not user:
        return jsonify({
            "error": "User not found."
        }), 404

    reference.update({
        "suspended": True
    })

    return jsonify({
        "success": True,
        "message": "User suspended."
    })


@app.route(
    "/api/admin/user/<uid>/activate",
    methods=["POST"]
)
@require_admin
def activate_user(uid):

    reference = user_reference(uid)

    user = reference.get()

    if not user:
        return jsonify({
            "error": "User not found."
        }), 404

    reference.update({
        "suspended": False
    })

    return jsonify({
        "success": True,
        "message": "User activated."
    })


# ============================================
# ADMIN ADVERTISEMENT MANAGEMENT
# ============================================

@app.route("/api/admin/ads")
@require_admin
def admin_ads():

    records = db.reference("ads").get() or {}

    result = []

    for ad_id, ad in records.items():

        result.append({
            "id": ad_id,
            "title": ad.get("title", ""),
            "text": ad.get("text", ""),
            "url": ad.get("url", ""),
            "active": ad.get("active", False),
            "created_at": ad.get("created_at", 0)
        })

    result.sort(
        key=lambda item: item.get("created_at", 0),
        reverse=True
    )

    return jsonify({
        "ads": result
    })


@app.route(
    "/api/admin/ads",
    methods=["POST"]
)
@require_admin
def create_ad():

    data = request.get_json(silent=True) or {}

    title = str(data.get("title", "")).strip()
    text = str(data.get("text", "")).strip()
    url = str(data.get("url", "")).strip()

    if not title or not text:
        return jsonify({
            "error": "Title and text are required."
        }), 400

    if len(title) > 120 or len(text) > 2000:
        return jsonify({
            "error": "Title or text is too long."
        }), 400

    if url:

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return jsonify({
                "error": "Only HTTP and HTTPS links are allowed."
            }), 400

        if not parsed.netloc:
            return jsonify({
                "error": "Invalid URL."
            }), 400

    reference = db.reference("ads").push()

    reference.set({
        "title": title,
        "text": text,
        "url": url,
        "active": True,
        "created_at": current_time()
    })

    return jsonify({
        "success": True,
        "id": reference.key
    })


@app.route(
    "/api/admin/ads/<ad_id>/toggle",
    methods=["POST"]
)
@require_admin
def toggle_ad(ad_id):

    reference = db.reference(f"ads/{ad_id}")

    ad = reference.get()

    if not ad:
        return jsonify({
            "error": "Advertisement not found."
        }), 404

    reference.update({
        "active": not ad.get("active", False)
    })

    return jsonify({
        "success": True
    })


@app.route(
    "/api/admin/ads/<ad_id>/delete",
    methods=["DELETE"]
)
@require_admin
def delete_ad(ad_id):

    reference = db.reference(f"ads/{ad_id}")

    if not reference.get():
        return jsonify({
            "error": "Advertisement not found."
        }), 404

    reference.delete()

    return jsonify({
        "success": True
    })


# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(413)
def file_too_large(error):

    return jsonify({
        "error": f"File is too large. Maximum size is {MAX_UPLOAD_MB} MB."
    }), 413


@app.errorhandler(404)
def not_found(error):

    if request.path.startswith("/api/"):
        return jsonify({
            "error": "API endpoint not found."
        }), 404

    return "Page not found.", 404


@app.errorhandler(500)
def internal_error(error):

    app.logger.exception("Internal server error.")

    if request.path.startswith("/api/"):
        return jsonify({
            "error": "An internal server error occurred."
        }), 500

    return "An internal server error occurred.", 500


# ============================================
# RUN APPLICATION
# ============================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
