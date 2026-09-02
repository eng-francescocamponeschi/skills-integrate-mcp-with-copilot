"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import hashlib
import hmac
import json
import sqlite3
import secrets
import time
from fastapi import Cookie, FastAPI, HTTPException, Response
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os
from pathlib import Path

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

with open(current_dir / "teachers.json", encoding="utf-8") as teachers_file:
    teachers = json.load(teachers_file)["teachers"]

SESSION_TTL = 8 * 60 * 60
session_db = current_dir / "sessions.sqlite3"


def initialize_session_store():
    with sqlite3.connect(session_db) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS sessions "
            "(session_id TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        connection.execute("CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)")


initialize_session_store()


class LoginRequest(BaseModel):
    username: str
    password: str


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()


def get_teacher(session_id):
    if not session_id:
        raise HTTPException(status_code=401, detail="Teacher login required")
    now = time.time()
    with sqlite3.connect(session_db) as connection:
        row = connection.execute(
            "SELECT username FROM sessions WHERE session_id = ? AND expires_at > ?",
            (session_id, now),
        ).fetchone()
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    username = row[0] if row else None
    if not username:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/login")
def login(login_request: LoginRequest, response: Response):
    teacher = next((item for item in teachers
                    if item["username"] == login_request.username), None)
    if not teacher:
        raise HTTPException(status_code=401, detail="Invalid teacher credentials")

    hash_parts = teacher.get("password_hash", "").split("$")
    if len(hash_parts) != 4 or hash_parts[:2] != ["pbkdf2_sha256", "600000"]:
        raise HTTPException(status_code=401, detail="Invalid teacher credentials")
    _, _, salt, expected_hash = hash_parts
    actual_hash = hash_password(login_request.password, salt)
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise HTTPException(status_code=401, detail="Invalid teacher credentials")

    session_id = secrets.token_urlsafe(32)
    with sqlite3.connect(session_db) as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        connection.execute(
            "INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)",
            (session_id, login_request.username, time.time() + SESSION_TTL),
        )
    response.set_cookie(
        "teacher_session", session_id, max_age=SESSION_TTL, httponly=True, samesite="lax"
    )
    return {"username": login_request.username}


@app.get("/auth/session")
def session(teacher_session: str | None = Cookie(default=None)):
    return {"username": get_teacher(teacher_session)}


@app.post("/auth/logout")
def logout(response: Response, teacher_session: str | None = Cookie(default=None)):
    if teacher_session:
        with sqlite3.connect(session_db) as connection:
            connection.execute("DELETE FROM sessions WHERE session_id = ?", (teacher_session,))
    response.delete_cookie("teacher_session")
    return {"message": "Logged out"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str,
                         teacher_session: str | None = Cookie(default=None)):
    """Sign up a student for an activity"""
    get_teacher(teacher_session)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str,
                             teacher_session: str | None = Cookie(default=None)):
    """Unregister a student from an activity"""
    get_teacher(teacher_session)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
