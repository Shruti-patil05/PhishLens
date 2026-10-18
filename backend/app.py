
import os
import json
from urllib.parse import urlparse

import mysql.connector
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app)


def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "phishlens_db")
    )


def score_url(url):
    candidate = url if "://" in url else "http://" + url
    parsed = urlparse(candidate)

    host = parsed.hostname or ""
    path = parsed.path.lower()
    full_url = candidate.lower()

    score = 0
    reasons = []

    if parsed.scheme.lower() != "https":
        score += 15
        reasons.append("URL does not use HTTPS: +15")

    suspicious_words = [
        "login", "verify", "account", "password",
        "wallet", "secure", "banking", "signin",
        "credential", "confirm", "reset"
    ]

    found_words = [
        word for word in suspicious_words
        if word in full_url
    ]

    if found_words:
        points = min(15 * len(found_words), 45)
        score += points
        reasons.append(
            f"Contains suspicious keywords "
            f"({', '.join(found_words)}): +{points}"
        )

    if len(url) > 90:
        score += 10
        reasons.append("URL is unusually long: +10")

    if host.count("-") >= 2:
        score += 15
        reasons.append(
            "Hostname contains multiple hyphens: +15"
        )

    sensitive_segments = {
        "login", "verify", "account", "password",
        "reset", "wallet", "signin", "credential"
    }

    path_parts = [
        part for part in path.split("/")
        if part in sensitive_segments
    ]

    if len(path_parts) >= 3:
        score += 20
        reasons.append(
            "Multiple sensitive URL path segments: +20"
        )

    score = min(score, 100)

    if score >= 70:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    if not reasons:
        reasons.append(
            "No configured warning patterns were detected."
        )

    return score, level, reasons


@app.get("/api/health")
def health():
    db = None

    try:
        db = get_db()
        return jsonify({
            "status": "ok",
            "database": "connected"
        })
    except Exception:
        app.logger.exception("Database health check failed")
        return jsonify({
            "status": "error",
            "database": "disconnected",
            "message": "Could not connect to MySQL."
        }), 503
    finally:
        if db is not None and db.is_connected():
            db.close()


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({
            "error": "Please enter a URL."
        }), 400

    candidate = url if "://" in url else "http://" + url
    parsed = urlparse(candidate)

    if (
        parsed.scheme.lower() not in ("http", "https")
        or not parsed.hostname
        or "." not in parsed.hostname
        or any(char.isspace() for char in url)
    ):
        return jsonify({
            "error": "Please enter a valid website URL."
        }), 400

    score, level, reasons = score_url(url)

    db = None
    cursor = None

    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO analysis_history
                (url, risk_score, risk_level, explanation)
            VALUES (%s, %s, %s, %s)
            """,
            (url, score, level, json.dumps(reasons))
        )

        record_id = cursor.lastrowid
        db.commit()

        return jsonify({
            "id": record_id,
            "url": url,
            "risk_score": score,
            "risk_level": level,
            "explanation": reasons
        })

    except Exception:
        if db is not None:
            db.rollback()

        app.logger.exception("URL analysis or database operation failed")

        return jsonify({
            "error": (
                "Analysis could not be saved. "
                "Check your MySQL connection and database tables."
            )
        }), 503

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None and db.is_connected():
            db.close()


@app.get("/api/dataset")
def dataset():
    db = None
    cursor = None

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, url, label, notes
            FROM phishing_urls
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()
        return jsonify(rows)

    except Exception:
        app.logger.exception("Dataset request failed")
        return jsonify({
            "error": "Could not load the dataset. Check MySQL tables."
        }), 503

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None and db.is_connected():
            db.close()


@app.get("/api/history")
def history():
    db = None
    cursor = None

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, url, risk_score, risk_level,
                   explanation, analyzed_at
            FROM analysis_history
            ORDER BY id DESC
            LIMIT 50
            """
        )

        rows = cursor.fetchall()

        for row in rows:
            explanation = row.get("explanation")

            if isinstance(explanation, str):
                try:
                    row["explanation"] = json.loads(explanation)
                except json.JSONDecodeError:
                    row["explanation"] = [explanation]

            if row.get("analyzed_at"):
                row["analyzed_at"] = (
                    row["analyzed_at"].isoformat()
                )

        return jsonify(rows)

    except Exception:
        app.logger.exception("History request failed")
        return jsonify({
            "error": "Could not load analysis history."
        }), 503

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None and db.is_connected():
            db.close()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
