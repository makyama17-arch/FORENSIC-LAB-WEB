import os
import json
import hashlib
import time
import uuid
import mimetypes
import tempfile
import io
import logging

from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file
)

from werkzeug.utils import secure_filename

import firebase_admin
from firebase_admin import credentials, auth, db

from PIL import (
    Image,
    ExifTags,
    UnidentifiedImageError
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)
from reportlab.lib.enums import TA_CENTER
from xml.sax.saxutils import escape


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

logging.basicConfig(level=logging.INFO)


# ============================================
# FIREBASE INITIALIZATION
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
            "Firebase service account is missing."
        )
        return False

    try:

        service_account = json.loads(
            service_account_json
        )

        credential = credentials.Certificate(
            service_account
        )

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


def utc_datetime():

    return datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")


def generate_case_id():

    return "FL-" + uuid.uuid4().hex[:12].upper()


def generate_evidence_id():

    return "EVD-" + uuid.uuid4().hex[:12].upper()


# ============================================
# AUTHENTICATION
# ============================================

def get_token_user():

    if not database_ready():

        raise RuntimeError(
            "Firebase is not configured."
        )

    header = request.headers.get(
        "Authorization", ""
    )

    if not header.startswith("Bearer "):

        raise PermissionError(
            "Authentication required."
        )

    token = header.split(
        " ", 1
    )[1].strip()

    if not token:

        raise PermissionError(
            "Invalid authentication token."
        )

    return auth.verify_id_token(token)


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

            return jsonify({
                "error": str(error)
            }), 401

        except RuntimeError as error:

            return jsonify({
                "error": str(error)
            }), 503

        except Exception:

            app.logger.exception(
                "Authentication failed."
            )

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
# FILE HASH CALCULATION
# ============================================

def calculate_hashes(file_path):

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    file_size = 0

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            file_size += len(chunk)

            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "file_size": file_size,
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest()
    }


# ============================================
# SAFE METADATA CONVERSION
# ============================================

def safe_value(value):

    try:

        if isinstance(value, bytes):

            return value.hex()[:500]

        if isinstance(value, tuple):

            return [
                safe_value(item)
                for item in value
            ]

        if isinstance(value, list):

            return [
                safe_value(item)
                for item in value
            ]

        if isinstance(value, dict):

            return {
                str(key): safe_value(val)
                for key, val in value.items()
            }

        if isinstance(value, (str, int, float, bool)):

            return value

        return str(value)[:500]

    except Exception:

        return "Unavailable"


# ============================================
# GPS CONVERSION
# ============================================

def gps_to_decimal(coordinate, reference):

    try:

        degrees = float(coordinate[0])
        minutes = float(coordinate[1])
        seconds = float(coordinate[2])

        decimal = (
            degrees +
            minutes / 60 +
            seconds / 3600
        )

        if reference in ("S", "W"):

            decimal = -decimal

        return round(decimal, 7)

    except Exception:

        return None


def extract_gps(exif):

    gps_data = exif.get(34853)

    if not gps_data:
        return None

    try:

        gps = {}

        for key, value in gps_data.items():

            tag_name = ExifTags.GPSTAGS.get(
                key, str(key)
            )

            gps[tag_name] = value

        latitude = gps_to_decimal(
            gps.get("GPSLatitude"),
            gps.get("GPSLatitudeRef")
        )

        longitude = gps_to_decimal(
            gps.get("GPSLongitude"),
            gps.get("GPSLongitudeRef")
        )

        if latitude is None or longitude is None:

            return {
                "available": True,
                "raw_metadata": {
                    str(key): safe_value(value)
                    for key, value in gps.items()
                }
            }

        return {
            "available": True,
            "latitude": latitude,
            "longitude": longitude
        }

    except Exception:

        return {
            "available": True,
            "message": "GPS metadata exists but could not be interpreted."
        }


# ============================================
# IMAGE FORENSICS ENGINE
# ============================================

def analyze_image(file_path):

    result = {
        "is_image": False,
        "image_analysis": {},
        "exif_metadata": {},
        "findings": [],
        "warnings": []
    }

    try:

        with Image.open(file_path) as image:

            result["is_image"] = True

            image_format = image.format or "Unknown"

            width, height = image.size

            image_info = image.info or {}

            exif = image.getexif()

            exif_data = {}

            for tag_id, value in exif.items():

                tag_name = ExifTags.TAGS.get(
                    tag_id, str(tag_id)
                )

                exif_data[tag_name] = safe_value(value)

            gps = extract_gps(exif)

            image_analysis = {

                "format": image_format,

                "width": width,

                "height": height,

                "resolution": f"{width} x {height}",

                "color_mode": image.mode,

                "bands": list(image.getbands()),

                "has_transparency": (
                    "A" in image.getbands()
                    or "transparency" in image_info
                ),

                "icc_profile_present": bool(
                    image_info.get("icc_profile")
                ),

                "exif_present": bool(exif_data),

                "metadata_fields": len(exif_data),

                "file_format_description": image_format

            }

            if image_format == "JPEG":

                image_analysis["compression"] = "JPEG lossy compression"

            elif image_format == "PNG":

                image_analysis["compression"] = "PNG compression"

            elif image_format == "WEBP":

                image_analysis["compression"] = "WebP"

            else:

                image_analysis["compression"] = "Not determined"

            result["image_analysis"] = image_analysis

            result["exif_metadata"] = exif_data

            result["gps_metadata"] = gps

            findings = []

            if width <= 0 or height <= 0:

                findings.append({
                    "severity": "Warning",
                    "title": "Invalid image dimensions",
                    "description": "The image dimensions are invalid."
                })

            else:

                findings.append({
                    "severity": "Information",
                    "title": "Image dimensions identified",
                    "description": (
                        f"The image dimensions are "
                        f"{width} x {height} pixels."
                    )
                })

            if exif_data:

                findings.append({
                    "severity": "Information",
                    "title": "EXIF metadata detected",
                    "description": (
                        f"{len(exif_data)} EXIF metadata "
                        "fields were identified."
                    })

            else:

                findings.append({
                    "severity": "Information",
                    "title": "EXIF metadata unavailable",
                    "description": (
                        "No standard EXIF fields were detected. "
                        "Metadata may have been removed or the "
                        "image format may not contain EXIF data."
                    )
                })

            software = (
                exif_data.get("Software")
                or image_info.get("software")
            )

            if software:

                findings.append({
                    "severity": "Review",
                    "title": "Software metadata identified",
                    "description": (
                        "Software information was found: "
                        + str(software)
                    )
                })

            if gps and gps.get("available"):

                findings.append({
                    "severity": "Information",
                    "title": "GPS metadata detected",
                    "description": (
                        "The image contains GPS-related metadata."
                    )
                })

            else:

                findings.append({
                    "severity": "Information",
                    "title": "GPS metadata unavailable",
                    "description": (
                        "No interpretable GPS metadata was detected."
                    )
                })

            result["findings"] = findings

            result["warnings"].append(
                "Metadata can be modified, removed or fabricated."
            )

            result["warnings"].append(
                "The presence of editing software metadata does not "
                "prove that an image was manipulated."
            )

            result["warnings"].append(
                "This analysis does not establish image authenticity."
            )

            return result

    except UnidentifiedImageError:

        result["warnings"].append(
            "The uploaded file could not be identified as a supported image."
        )

        return result

    except Exception:

        app.logger.exception(
            "Image analysis failed."
        )

        result["warnings"].append(
            "Image analysis could not be completed."
        )

        return result


# ============================================
# FORENSIC REPORT GENERATOR
# ============================================

def build_forensic_report(
    filename,
    hashes,
    image_result,
    case_id,
    evidence_id,
    examiner
):

    file_size = hashes["file_size"]

    mime_type = (
        mimetypes.guess_type(filename)[0]
        or "application/octet-stream"
    )

    findings = image_result.get(
        "findings", []
    )

    warnings = image_result.get(
        "warnings", []
    )

    if image_result.get("is_image"):

        analysis_type = "Image Forensics"

        conclusion = (
            "Image technical information and available metadata "
            "were examined. No definitive authenticity conclusion "
            "can be made from this automated examination alone."
        )

    else:

        analysis_type = "General File Identification"

        conclusion = (
            "File identification and cryptographic hashing "
            "were completed. Detailed format-specific examination "
            "was not performed for this file type."
        )

    report = {

        "case_id": case_id,

        "evidence_id": evidence_id,

        "examiner": examiner,

        "analysis_date": utc_datetime(),

        "created_at": current_time(),

        "filename": filename,

        "mime_type": mime_type,

        "file_size": file_size,

        "file_size_mb": round(
            file_size / (1024 * 1024), 3
        ),

        "hashes": hashes,

        "analysis_type": analysis_type,

        "is_image": image_result.get("is_image", False),

        "image_analysis": image_result.get(
            "image_analysis", {}
        ),

        "exif_metadata": image_result.get(
            "exif_metadata", {}
        ),

        "gps_metadata": image_result.get(
            "gps_metadata"
        ),

        "findings": findings,

        "warnings": warnings,

        "conclusion": conclusion,

        "limitations": [

            "Automated analysis is not a substitute for a complete forensic examination.",

            "Metadata may be modified, removed or fabricated.",

            "Hash values identify file contents but do not prove authenticity.",

            "No original device examination was performed.",

            "No conclusion about who created or edited the file is made."

        ]

    }

    return report


# ============================================
# PDF REPORT STYLES
# ============================================

def make_pdf_styles():

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#123456"),
            spaceAfter=12
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#123456"),
            spaceBefore=12,
            spaceAfter=7
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportText",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            spaceAfter=4
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallReportText",
            parent=styles["BodyText"],
            fontSize=7,
            leading=10
        )
    )

    return styles


# ============================================
# PDF TABLE HELPER
# ============================================

def pdf_table(rows, col_widths=None):

    table = Table(
        rows,
        colWidths=col_widths,
        repeatRows=1
    )

    table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#123456")
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.grey
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )

        ])
    )

    return table


# ============================================
# PDF REPORT GENERATION
# ============================================

def generate_pdf(report):

    buffer = io.BytesIO()

    document = SimpleDocTemplate(

        buffer,

        pagesize=A4,

        rightMargin=17 * mm,

        leftMargin=17 * mm,

        topMargin=18 * mm,

        bottomMargin=18 * mm

    )

    styles = make_pdf_styles()

    story = []

    def heading(text):

        story.append(
            Paragraph(
                escape(text),
                styles["SectionHeading"]
            )
        )

    def paragraph(text):

        story.append(
            Paragraph(
                escape(str(text)),
                styles["ReportText"]
            )
        )

    def table_value(value):

        return Paragraph(
            escape(str(value)),
            styles["SmallReportText"]
        )

    # COVER

    story.append(
        Spacer(1, 20 * mm)
    )

    story.append(
        Paragraph(
            "FORENSIC LAB",
            styles["ReportTitle"]
        )
    )

    story.append(
        Paragraph(
            "DIGITAL FORENSIC EXAMINATION REPORT",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(1, 12 * mm)
    )

    story.append(
        Paragraph(
            "AUTOMATED FORENSIC ANALYSIS",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(1, 10 * mm)
    )

    # CASE INFORMATION

    heading("1. CASE INFORMATION")

    rows = [

        ["Field", "Value"],

        ["Case ID", report["case_id"]],

        ["Evidence ID", report["evidence_id"]],

        ["Examiner", report["examiner"]],

        ["Analysis Date", report["analysis_date"]],

        ["Analysis Type", report["analysis_type"]]

    ]

    story.append(
        pdf_table(rows, [55 * mm, 110 * mm])
    )

    # FILE IDENTIFICATION

    heading("2. FILE IDENTIFICATION")

    rows = [

        ["Field", "Value"],

        ["Filename", report["filename"]],

        ["MIME Type", report["mime_type"]],

        ["File Size", f'{report["file_size"]} bytes'],

        ["File Size MB", report["file_size_mb"]],

        ["SHA-256", report["hashes"]["sha256"]],

        ["SHA-1", report["hashes"]["sha1"]],

        ["MD5", report["hashes"]["md5"]]

    ]

    story.append(
        pdf_table(rows, [55 * mm, 110 * mm])
    )

    # IMAGE ANALYSIS

    heading("3. IMAGE TECHNICAL ANALYSIS")

    if report["is_image"]:

        image = report["image_analysis"]

        rows = [

            ["Property", "Result"],

            ["Format", image.get("format", "Unavailable")],

            ["Width", image.get("width", "Unavailable")],

            ["Height", image.get("height", "Unavailable")],

            ["Resolution", image.get("resolution", "Unavailable")],

            ["Color Mode", image.get("color_mode", "Unavailable")],

            ["Bands", image.get("bands", "Unavailable")],

            ["Transparency", image.get("has_transparency", "Unavailable")],

            ["Compression", image.get("compression", "Unavailable")],

            ["ICC Profile", image.get("icc_profile_present", False)],

            ["EXIF Present", image.get("exif_present", False)]

        ]

        story.append(
            pdf_table(rows, [55 * mm, 110 * mm])
        )

    else:

        paragraph(
            "This file was not identified as a supported image. "
            "Image-specific examination was not performed."
        )

    # EXIF

    heading("4. EXIF METADATA")

    exif = report.get(
        "exif_metadata", {}
    )

    if exif:

        rows = [
            ["Metadata Field", "Value"]
        ]

        for key, value in exif.items():

            rows.append([
                table_value(key),
                table_value(str(value))
            ])

        story.append(
            pdf_table(rows, [55 * mm, 110 * mm])
        )

    else:

        paragraph(
            "No standard EXIF metadata fields were detected."
        )

    # GPS

    heading("5. GPS INFORMATION")

    gps = report.get("gps_metadata")

    if gps and gps.get("available"):

        if "latitude" in gps:

            paragraph(
                "Latitude: " + str(gps["latitude"])
            )

            paragraph(
                "Longitude: " + str(gps["longitude"])
            )

        else:

            paragraph(
                gps.get(
                    "message",
                    "GPS metadata was detected."
                )
            )

    else:

        paragraph(
            "No interpretable GPS coordinates were detected."
        )

    # FINDINGS

    heading("6. FORENSIC FINDINGS")

    findings = report.get("findings", [])

    if findings:

        rows = [
            ["Severity", "Finding", "Description"]
        ]

        for finding in findings:

            rows.append([

                table_value(
                    finding.get("severity", "Information")
                ),

                table_value(
                    finding.get("title", "")
                ),

                table_value(
                    finding.get("description", "")
                )

            ])

        story.append(
            pdf_table(
                rows,
                [30 * mm, 45 * mm, 90 * mm]
            )
        )

    else:

        paragraph(
            "No additional findings were recorded."
        )

    # WARNINGS

    heading("7. EXAMINATION WARNINGS")

    for warning in report.get("warnings", []):

        paragraph("• " + warning)

    # CONCLUSION

    heading("8. EXAMINER'S CONCLUSION")

    paragraph(
        report["conclusion"]
    )

    # LIMITATIONS

    heading("9. EXAMINATION LIMITATIONS")

    for limitation in report.get("limitations", []):

        paragraph("• " + limitation)

    # FINAL NOTICE

    story.append(
        Spacer(1, 12 * mm)
    )

    story.append(
        Paragraph(
            "FORENSIC LAB | END OF REPORT",
            styles["Heading2"]
        )
    )

    paragraph(
        "This report was generated automatically by FORENSIC LAB. "
        "It records the results of the examination performed by "
        "the software. It is not, by itself, a certification of "
        "authenticity or a substitute for expert forensic testimony."
    )

    def add_page_number(canvas, doc):

        canvas.saveState()

        canvas.setFont(
            "Helvetica",
            8
        )

        canvas.drawString(
            17 * mm,
            10 * mm,
            "FORENSIC LAB - CONFIDENTIAL EXAMINATION REPORT"
        )

        canvas.drawRightString(
            A4[0] - 17 * mm,
            10 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    buffer.seek(0)

    return buffer


# ============================================
# PUBLIC WEBSITE PAGES
# ============================================

@app.route("/")
def home():

    return render_template("index.html")


@app.route("/auth")
def authentication():

    return render_template(
        "auth.html",
        open_register=False
    )


@app.route("/register")
def register():

    return render_template(
        "auth.html",
        open_register=True
    )


@app.route("/create-account")
def create_account():

    return render_template(
        "auth.html",
        open_register=True
    )


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

            reference.update({
                "name": name
            })

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

    return jsonify({
        "success": True
    })


# ============================================
# FULL FORENSIC ANALYSIS
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

    filename = secure_filename(
        uploaded_file.filename
    )

    if not filename:

        return jsonify({
            "error": "Invalid filename."
        }), 400

    temporary_path = None

    try:

        # Store temporary upload securely

        with tempfile.NamedTemporaryFile(
            delete=False
        ) as temporary_file:

            temporary_path = temporary_file.name

            uploaded_file.save(
                temporary_file
            )

        # Calculate cryptographic hashes

        hashes = calculate_hashes(
            temporary_path
        )

        # Examine image metadata

        image_result = analyze_image(
            temporary_path
        )

        # Generate case and evidence identifiers

        case_id = generate_case_id()

        evidence_id = generate_evidence_id()

        uid = request.current_user["uid"]

        user = get_user(uid)

        examiner = (
            user.get("name")
            or request.current_user.get("email")
            or "Unknown Examiner"
        )

        # Build forensic report

        report = build_forensic_report(

            filename,

            hashes,

            image_result,

            case_id,

            evidence_id,

            examiner

        )

        # Store report metadata in Firebase

        history_reference = db.reference(
            f"history/{uid}"
        ).push()

        report_id = history_reference.key

        report["report_id"] = report_id

        report["user_uid"] = uid

        history_reference.set(report)

        return jsonify({

            "success": True,

            "report_id": report_id,

            "case_id": case_id,

            "evidence_id": evidence_id,

            "filename": filename,

            "size": hashes["file_size"],

            "sha256": hashes["sha256"],

            "sha1": hashes["sha1"],

            "md5": hashes["md5"],

            "analysis_type": report["analysis_type"],

            "is_image": report["is_image"],

            "image_analysis": report["image_analysis"],

            "exif_metadata": report["exif_metadata"],

            "gps_metadata": report.get("gps_metadata"),

            "findings": report["findings"],

            "warnings": report["warnings"],

            "conclusion": report["conclusion"],

            "message": (
                "Forensic examination completed successfully."
            ),

            "report_url": f"/api/report/{report_id}"

        })

    except Exception:

        app.logger.exception(
            "Forensic analysis failed."
        )

        return jsonify({

            "error": (
                "Forensic analysis failed. "
                "Please try again."
            )

        }), 500

    finally:

        if temporary_path and os.path.exists(
            temporary_path
        ):

            try:

                os.remove(
                    temporary_path
                )

            except OSError:

                app.logger.warning(
                    "Temporary file could not be removed."
                )


# ============================================
# DOWNLOAD PDF REPORT
# ============================================

@app.route("/api/report/<report_id>")
@require_auth
def download_report():

    uid = request.current_user["uid"]

    report_id = request.view_args["report_id"]

    report = db.reference(
        f"history/{uid}/{report_id}"
    ).get()

    if not report:

        return jsonify({
            "error": "Forensic report not found."
        }), 404

    try:

        pdf_buffer = generate_pdf(
            report
        )

        filename = (
            f"FORENSIC_REPORT_{report.get('case_id', report_id)}.pdf"
        )

        return send_file(

            pdf_buffer,

            mimetype="application/pdf",

            as_attachment=True,

            download_name=filename

        )

    except Exception:

        app.logger.exception(
            "PDF report generation failed."
        )

        return jsonify({
            "error": "Unable to generate PDF report."
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

        key=lambda item: item.get(
            "created_at", 0
        ),

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

    records = db.reference(
        "ads"
    ).get() or {}

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

    users = db.reference(
        "users"
    ).get() or {}

    ads = db.reference(
        "ads"
    ).get() or {}

    now = current_time()

    five_minutes = 5 * 60 * 1000

    seven_days = 7 * 24 * 60 * 60 * 1000

    online_users = 0

    weekly_users = 0

    active_ads = 0

    for user in users.values():

        last_seen = user.get(
            "last_seen", 0
        )

        created_at = user.get(
            "created_at", 0
        )

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

    users = db.reference(
        "users"
    ).get() or {}

    result = []

    for uid, user in users.items():

        result.append({

            "uid": uid,

            "name": user.get("name", ""),

            "email": user.get("email", ""),

            "suspended": user.get(
                "suspended", False
            ),

            "created_at": user.get(
                "created_at", 0
            ),

            "last_seen": user.get(
                "last_seen", 0
            )

        })

    result.sort(

        key=lambda item: item.get(
            "created_at", 0
        ),

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

    records = db.reference(
        "ads"
    ).get() or {}

    result = []

    for ad_id, ad in records.items():

        result.append({

            "id": ad_id,

            "title": ad.get("title", ""),

            "text": ad.get("text", ""),

            "url": ad.get("url", ""),

            "active": ad.get(
                "active", False
            ),

            "created_at": ad.get(
                "created_at", 0
            )

        })

    result.sort(

        key=lambda item: item.get(
            "created_at", 0
        ),

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

    data = request.get_json(
        silent=True
    ) or {}

    title = str(
        data.get("title", "")
    ).strip()

    text = str(
        data.get("text", "")
    ).strip()

    url = str(
        data.get("url", "")
    ).strip()

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

        if parsed.scheme not in (
            "http", "https"
        ):

            return jsonify({
                "error": "Only HTTP and HTTPS links are allowed."
            }), 400

        if not parsed.netloc:

            return jsonify({
                "error": "Invalid URL."
            }), 400

    reference = db.reference(
        "ads"
    ).push()

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

    reference = db.reference(
        f"ads/{ad_id}"
    )

    ad = reference.get()

    if not ad:

        return jsonify({
            "error": "Advertisement not found."
        }), 404

    reference.update({

        "active": not ad.get(
            "active", False
        )

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

    reference = db.reference(
        f"ads/{ad_id}"
    )

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

        "error": (
            f"File is too large. "
            f"Maximum size is {MAX_UPLOAD_MB} MB."
        )

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

    app.logger.exception(
        "Internal server error."
    )

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

        port=int(
            os.environ.get("PORT", 5000)
        ),

        debug=False

    )
