"""
지각하지말자 - 택시 합승 매칭 앱 (백엔드)

기능
  1. 일반 회원가입 / 로그인 (아이디 + 닉네임 + 비밀번호)
  2. 출발역(부산 내 모든 역) + 도착 대학(부산 내 모든 대학)을 고르면
     "같은 출발역 + 같은 대학"을 고른 사람끼리 대기열에서 매칭
       - 4명이 모이면 즉시 채팅방 오픈
       - 2~3명이면 10초 뒤 채팅방 오픈
  3. 매칭되면 실시간 채팅 (Socket.IO)

실행:  python app.py   →  http://localhost:5000
"""
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, render_template, request, session
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import check_password_hash, generate_password_hash

from places import ALL_STATIONS, ALL_UNIVERSITIES, STATION_GROUPS, UNIVERSITY_GROUPS

# ──────────────── 설정 ────────────────
APP_NAME = "지각하지말자"
MIN_PEOPLE, MAX_PEOPLE = 2, 4                                         # 매칭 인원
MATCH_WAIT_SECONDS = int(os.environ.get("MATCH_WAIT_SECONDS", "10"))  # 2~3명일 때 기다리는 시간
DB_PATH = os.environ.get("DB_PATH", "jigak.db")
USERNAME_RE = re.compile(r"^[a-z0-9_]{4,16}$")
# ───────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
socketio = SocketIO(app, async_mode="threading")


# ──────────────── DB ────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    origin TEXT NOT NULL,
    dest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE TABLE IF NOT EXISTS room_members(
    room_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    left_at TEXT,
    PRIMARY KEY(room_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER NOT NULL,
    user_id INTEGER,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def run(sql, args=(), one=False, write=False):
    """SQL 한 줄 실행. write=True면 커밋 후 lastrowid 반환, 아니면 조회 결과 반환."""
    conn = db()
    try:
        cur = conn.execute(sql, args)
        if write:
            conn.commit()
            return cur.lastrowid
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()


def init_db():
    conn = db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# ──────────────── 로그인 도우미 ────────────────
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return run("SELECT * FROM users WHERE id=?", (uid,), one=True)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify(error="로그인이 필요해요."), 401
        return fn(user, *args, **kwargs)
    return wrapper


def user_payload(u):
    return {"id": u["id"], "username": u["username"], "nickname": u["nickname"]}


# ──────────────── 방 도우미 ────────────────
def is_member(uid, rid):
    row = run(
        "SELECT 1 FROM room_members rm JOIN rooms r ON r.id = rm.room_id "
        "WHERE rm.room_id=? AND rm.user_id=? AND rm.left_at IS NULL AND r.closed_at IS NULL",
        (rid, uid), one=True,
    )
    return row is not None


def active_room_id(uid):
    row = run(
        "SELECT rm.room_id FROM room_members rm JOIN rooms r ON r.id = rm.room_id "
        "WHERE rm.user_id=? AND rm.left_at IS NULL AND r.closed_at IS NULL "
        "ORDER BY rm.room_id DESC LIMIT 1",
        (uid,), one=True,
    )
    return row["room_id"] if row else None


def members_of(rid):
    rows = run(
        "SELECT u.id, u.nickname FROM room_members rm JOIN users u ON u.id = rm.user_id "
        "WHERE rm.room_id=? AND rm.left_at IS NULL ORDER BY u.id",
        (rid,),
    )
    return [{"id": r["id"], "nickname": r["nickname"]} for r in rows]


def post_system(rid, text):
    created = now()
    mid = run(
        "INSERT INTO messages(room_id, user_id, text, created_at) VALUES (?,NULL,?,?)",
        (rid, text, created), write=True,
    )
    socketio.emit(
        "message",
        {"id": mid, "room_id": rid, "user_id": None, "nickname": None, "text": text, "created_at": created},
        to=f"room:{rid}",
    )


# ──────────────── 매칭 ────────────────
# waiting[user_id] = {"since": 대기 시작 시각, "origin": 출발역, "dest": 도착 대학}
waiting = {}
waiting_lock = threading.Lock()


def create_room(origin, dest, user_ids):
    conn = db()
    try:
        rid = conn.execute(
            "INSERT INTO rooms(origin, dest, created_at) VALUES (?,?,?)", (origin, dest, now())
        ).lastrowid
        conn.executemany(
            "INSERT INTO room_members(room_id, user_id) VALUES (?,?)", [(rid, u) for u in user_ids]
        )
        conn.execute(
            "INSERT INTO messages(room_id, user_id, text, created_at) VALUES (?,NULL,?,?)",
            (rid, f"{len(user_ids)}명이 모였어요. 인사하고 만날 위치와 시간을 정해보세요.", now()),
        )
        conn.commit()
    finally:
        conn.close()
    return rid


def try_match():
    """같은 (출발역, 도착 대학)을 고른 대기자끼리 방을 만든다.
    - 4명이 모이면 즉시 매칭
    - 2~3명이면 가장 오래 기다린 사람이 MATCH_WAIT_SECONDS(10초) 이상 기다렸을 때 매칭
    """
    created = []
    with waiting_lock:
        groups = {}
        for uid, w in waiting.items():
            groups.setdefault((w["origin"], w["dest"]), []).append((uid, w["since"]))

        for (origin, dest), members in groups.items():
            members.sort(key=lambda m: m[1])  # 오래 기다린 순
            while members:
                n = len(members)
                oldest_wait = time.time() - members[0][1]
                if n >= MAX_PEOPLE:
                    take = MAX_PEOPLE
                elif n >= MIN_PEOPLE and oldest_wait >= MATCH_WAIT_SECONDS:
                    take = n
                else:
                    break
                batch, members = members[:take], members[take:]
                ids = [uid for uid, _ in batch]
                for uid in ids:
                    waiting.pop(uid, None)
                created.append((create_room(origin, dest, ids), ids))

    for rid, ids in created:
        for uid in ids:
            socketio.emit("matched", {"room_id": rid}, to=f"user:{uid}")


def matcher_loop():
    while True:
        try:
            try_match()
        except Exception as e:
            print("매칭 오류:", e, flush=True)
        socketio.sleep(1)


def queue_status(uid):
    with waiting_lock:
        w = waiting.get(uid)
        if not w:
            return {"waiting": False, "count": 0, "elapsed": 0, "origin": None, "dest": None}
        same_route = sum(
            1 for x in waiting.values() if x["origin"] == w["origin"] and x["dest"] == w["dest"]
        )
        return {
            "waiting": True,
            "count": same_route,
            "elapsed": int(time.time() - w["since"]),
            "origin": w["origin"],
            "dest": w["dest"],
        }


# ──────────────── 페이지 ────────────────
@app.get("/")
def index():
    cfg = {
        "name": APP_NAME,
        "min": MIN_PEOPLE,
        "max": MAX_PEOPLE,
        "wait": MATCH_WAIT_SECONDS,
        "stations": [{"label": label, "items": items} for label, items in STATION_GROUPS],
        "universities": [{"label": label, "items": items} for label, items in UNIVERSITY_GROUPS],
    }
    return render_template("index.html", cfg=cfg)


# ──────────────── API: 회원가입 / 로그인 ────────────────
@app.post("/api/signup")
def signup():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip().lower()
    nickname = (d.get("nickname") or "").strip()
    password = d.get("password") or ""

    if not USERNAME_RE.match(username):
        return jsonify(error="아이디는 영문 소문자, 숫자, _ 로 4~16자만 쓸 수 있어요."), 400
    if not 2 <= len(nickname) <= 12:
        return jsonify(error="닉네임은 2~12자로 입력해주세요."), 400
    if len(password) < 8:
        return jsonify(error="비밀번호는 8자 이상이어야 해요."), 400

    try:
        uid = run(
            "INSERT INTO users(username, nickname, pw_hash, created_at) VALUES (?,?,?,?)",
            (username, nickname, generate_password_hash(password), now()), write=True,
        )
    except sqlite3.IntegrityError:
        if run("SELECT 1 FROM users WHERE username=?", (username,), one=True):
            return jsonify(error="이미 사용 중인 아이디예요."), 409
        return jsonify(error="이미 사용 중인 닉네임이에요."), 409

    session["uid"] = uid
    user = run("SELECT * FROM users WHERE id=?", (uid,), one=True)
    return jsonify(ok=True, user=user_payload(user))


@app.get("/api/check")
def check_duplicate():
    """회원가입 화면의 '중복확인' 버튼용. 쓸 수 있으면 available=True."""
    field = request.args.get("field")
    value = (request.args.get("value") or "").strip()

    if field == "username":
        value = value.lower()
        if not USERNAME_RE.match(value):
            return jsonify(available=False, message="아이디는 영문 소문자, 숫자, _ 로 4~16자만 쓸 수 있어요.")
        if run("SELECT 1 FROM users WHERE username=?", (value,), one=True):
            return jsonify(available=False, message="이미 사용 중인 아이디예요.")
        return jsonify(available=True, message="사용할 수 있는 아이디예요.")

    if field == "nickname":
        if not 2 <= len(value) <= 12:
            return jsonify(available=False, message="닉네임은 2~12자로 입력해주세요.")
        if run("SELECT 1 FROM users WHERE nickname=? COLLATE NOCASE", (value,), one=True):
            return jsonify(available=False, message="이미 사용 중인 닉네임이에요.")
        return jsonify(available=True, message="사용할 수 있는 닉네임이에요.")

    return jsonify(error="잘못된 요청이에요."), 400


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip().lower()
    password = d.get("password") or ""
    user = run("SELECT * FROM users WHERE username=?", (username,), one=True)
    if not user or not check_password_hash(user["pw_hash"], password):
        return jsonify(error="아이디 또는 비밀번호가 맞지 않아요."), 401
    session["uid"] = user["id"]
    return jsonify(ok=True, user=user_payload(user))


@app.post("/api/logout")
def logout():
    uid = session.pop("uid", None)
    if uid:
        with waiting_lock:
            waiting.pop(uid, None)
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    user = current_user()
    if not user:
        return jsonify(user=None)
    return jsonify(
        user=user_payload(user),
        queue=queue_status(user["id"]),
        room_id=active_room_id(user["id"]),
    )


# ──────────────── API: 매칭 ────────────────
@app.post("/api/queue/join")
@login_required
def queue_join(user):
    d = request.get_json(silent=True) or {}
    origin, dest = d.get("origin"), d.get("dest")
    if origin not in ALL_STATIONS:
        return jsonify(error="출발역을 선택해주세요."), 400
    if dest not in ALL_UNIVERSITIES:
        return jsonify(error="도착 대학을 선택해주세요."), 400
    if active_room_id(user["id"]):
        return jsonify(error="이미 참여 중인 채팅방이 있어요."), 409

    with waiting_lock:
        w = waiting.get(user["id"])
        if not w or w["origin"] != origin or w["dest"] != dest:
            waiting[user["id"]] = {"since": time.time(), "origin": origin, "dest": dest}
    try_match()
    return jsonify(queue=queue_status(user["id"]), room_id=active_room_id(user["id"]))


@app.post("/api/queue/leave")
@login_required
def queue_leave(user):
    with waiting_lock:
        waiting.pop(user["id"], None)
    return jsonify(queue=queue_status(user["id"]))


# ──────────────── API: 채팅방 ────────────────
@app.get("/api/room/<int:rid>")
@login_required
def room_info(user, rid):
    if not is_member(user["id"], rid):
        return jsonify(error="참여 중인 방이 아니에요."), 403
    room = run("SELECT origin, dest FROM rooms WHERE id=?", (rid,), one=True)
    rows = run(
        "SELECT m.id, m.user_id, m.text, m.created_at, u.nickname "
        "FROM messages m LEFT JOIN users u ON u.id = m.user_id "
        "WHERE m.room_id=? ORDER BY m.id DESC LIMIT 200",
        (rid,),
    )
    messages = [
        {
            "id": r["id"], "room_id": rid, "user_id": r["user_id"],
            "nickname": r["nickname"], "text": r["text"], "created_at": r["created_at"],
        }
        for r in reversed(rows)
    ]
    return jsonify(
        room_id=rid, origin=room["origin"], dest=room["dest"],
        members=members_of(rid), messages=messages,
    )


@app.post("/api/room/<int:rid>/leave")
@login_required
def room_leave(user, rid):
    if not is_member(user["id"], rid):
        return jsonify(ok=True)
    run(
        "UPDATE room_members SET left_at=? WHERE room_id=? AND user_id=?",
        (now(), rid, user["id"]), write=True,
    )
    remaining = members_of(rid)
    if remaining:
        post_system(rid, f"{user['nickname']}님이 나갔어요.")
        socketio.emit("members", {"room_id": rid, "members": remaining}, to=f"room:{rid}")
    else:
        run("UPDATE rooms SET closed_at=? WHERE id=?", (now(), rid), write=True)
    return jsonify(ok=True)


# ──────────────── Socket.IO ────────────────
last_sent = {}  # user_id -> 마지막 전송 시각 (도배 방지)


@socketio.on("connect")
def on_connect():
    uid = session.get("uid")
    if not uid:
        return False  # 로그인 안 한 연결은 거절
    join_room(f"user:{uid}")


@socketio.on("enter")
def on_enter(data):
    uid = session.get("uid")
    try:
        rid = int((data or {}).get("room_id", 0))
    except (TypeError, ValueError):
        return
    if uid and is_member(uid, rid):
        join_room(f"room:{rid}")


@socketio.on("send")
def on_send(data):
    uid = session.get("uid")
    data = data or {}
    try:
        rid = int(data.get("room_id", 0))
    except (TypeError, ValueError):
        return
    text = str(data.get("text") or "").strip()[:500]
    if not uid or not text or not is_member(uid, rid):
        return
    if time.time() - last_sent.get(uid, 0) < 0.3:
        return
    last_sent[uid] = time.time()

    created = now()
    mid = run(
        "INSERT INTO messages(room_id, user_id, text, created_at) VALUES (?,?,?,?)",
        (rid, uid, text, created), write=True,
    )
    user = run("SELECT nickname FROM users WHERE id=?", (uid,), one=True)
    emit(
        "message",
        {"id": mid, "room_id": rid, "user_id": uid, "nickname": user["nickname"],
         "text": text, "created_at": created},
        to=f"room:{rid}",
    )


if __name__ == "__main__":
    init_db()
    socketio.start_background_task(matcher_loop)
    # 배포 서비스(Render 등)는 PORT 환경변수로 포트를 알려줘요. 내 컴퓨터에서는 5000번을 써요.
    port = int(os.environ.get("PORT", "5000"))
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True, use_reloader=False)
