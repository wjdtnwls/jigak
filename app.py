"""
지각하지말자 - 택시 합승 매칭 앱 (백엔드)

기능
  1. 일반 회원가입 / 로그인 (아이디 + 닉네임 + 비밀번호), 아이디·닉네임 중복확인
  2. 출발역(부산 내 모든 역) + 도착 대학(부산 내 모든 대학)을 고르면
     "같은 출발역 + 같은 대학"을 고른 사람끼리 대기열에서 매칭
       - 4명이 모이면 즉시 채팅방 오픈
       - 2~3명이면 10초 뒤 채팅방 오픈
       - 서로 차단한 사람끼리는 같은 방에 묶이지 않음
  3. 예상 택시비 표시 (거리 기반 추정)
  4. 실시간 채팅 (Socket.IO), 빠른 메시지, 약속 장소 공유, 택시비 1/N 정산
  5. 신고 / 차단
  6. 마이페이지: 이용내역, 닉네임·비밀번호 변경, 차단 목록, 회원탈퇴

실행:  python app.py   →  http://localhost:5000
"""
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, render_template, request, session
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import check_password_hash, generate_password_hash

from places import (
    ALL_STATIONS, ALL_UNIVERSITIES, STATION_GROUPS, UNIVERSITY_GROUPS, estimate_fare,
)

# ──────────────── 설정 ────────────────
APP_NAME = "지각하지말자"
MIN_PEOPLE, MAX_PEOPLE = 2, 4                                         # 매칭 인원
MATCH_WAIT_SECONDS = int(os.environ.get("MATCH_WAIT_SECONDS", "10"))  # 2~3명일 때 기다리는 시간
DB_PATH = os.environ.get("DB_PATH", "jigak.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")                           # 설정하면 신고 목록을 볼 수 있어요
USERNAME_RE = re.compile(r"^[a-z0-9_]{4,16}$")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
REPORT_REASONS = ["비매너·욕설", "약속 불이행(노쇼)", "금전 요구·사기 의심", "부적절한 대화", "기타"]
FARE_MIN, FARE_MAX = 1000, 300000
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
CREATE TABLE IF NOT EXISTS blocks(
    blocker_id INTEGER NOT NULL,
    blocked_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(blocker_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS reports(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
"""

# 예전 버전 DB(jigak.db)에도 새 기능이 동작하도록, 없는 칸은 자동으로 추가해요.
ROOM_EXTRA_COLUMNS = [
    ("meet_place", "TEXT"),
    ("meet_time", "TEXT"),
    ("meet_by", "INTEGER"),
    ("fare_total", "INTEGER"),
    ("fare_payer", "INTEGER"),
    ("fare_people", "INTEGER"),
    ("fare_per", "INTEGER"),
]


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
    have = {r["name"] for r in conn.execute("PRAGMA table_info(rooms)")}
    for name, ddl in ROOM_EXTRA_COLUMNS:
        if name not in have:
            conn.execute(f"ALTER TABLE rooms ADD COLUMN {name} {ddl}")
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


def nickname_error(nickname, exclude_uid=None):
    """닉네임이 쓸 수 없으면 이유(문자열), 쓸 수 있으면 None."""
    if not 2 <= len(nickname) <= 12:
        return "닉네임은 2~12자로 입력해주세요."
    row = run("SELECT id FROM users WHERE nickname=? COLLATE NOCASE", (nickname,), one=True)
    if row and row["id"] != exclude_uid:
        return "이미 사용 중인 닉네임이에요."
    return None


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


def shared_room(a, b):
    """두 사람이 같은 방에 함께 있었던 적이 있는지 (신고/차단은 같이 탄 사람만 가능)."""
    row = run(
        "SELECT 1 FROM room_members x JOIN room_members y ON x.room_id = y.room_id "
        "WHERE x.user_id=? AND y.user_id=? LIMIT 1",
        (a, b), one=True,
    )
    return row is not None


def room_state(rid):
    """약속 장소 / 정산 정보 (화면 위쪽 안내 카드에 쓰여요)."""
    r = run("SELECT * FROM rooms WHERE id=?", (rid,), one=True)
    if not r:
        return None
    state = {"meet": None, "fare": None}
    if r["meet_place"]:
        by = run("SELECT nickname FROM users WHERE id=?", (r["meet_by"],), one=True)
        state["meet"] = {
            "place": r["meet_place"], "time": r["meet_time"], "by": by["nickname"] if by else None,
        }
    if r["fare_total"]:
        payer = run("SELECT nickname FROM users WHERE id=?", (r["fare_payer"],), one=True)
        state["fare"] = {
            "total": r["fare_total"], "people": r["fare_people"], "per": r["fare_per"],
            "payer_id": r["fare_payer"], "payer": payer["nickname"] if payer else None,
        }
    return state


def broadcast_state(rid):
    socketio.emit("room_state", {"room_id": rid, "state": room_state(rid)}, to=f"room:{rid}")


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


def leave_room_now(uid, nickname, rid):
    """방에서 나가기. 아무도 안 남으면 방을 닫아요."""
    run(
        "UPDATE room_members SET left_at=? WHERE room_id=? AND user_id=?",
        (now(), rid, uid), write=True,
    )
    remaining = members_of(rid)
    if remaining:
        post_system(rid, f"{nickname}님이 나갔어요.")
        socketio.emit("members", {"room_id": rid, "members": remaining}, to=f"room:{rid}")
    else:
        run("UPDATE rooms SET closed_at=? WHERE id=?", (now(), rid), write=True)


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
            (rid, f"{len(user_ids)}명이 모였어요. 인사하고 만날 장소와 시간을 정해보세요.", now()),
        )
        conn.commit()
    finally:
        conn.close()
    return rid


def load_block_pairs():
    """서로 한 번이라도 차단한 사람 쌍 (방향 상관없이)."""
    pairs = set()
    for r in run("SELECT blocker_id, blocked_id FROM blocks"):
        pairs.add((r["blocker_id"], r["blocked_id"]))
        pairs.add((r["blocked_id"], r["blocker_id"]))
    return pairs


def pick_batch(members, pairs, want):
    """대기자(오래 기다린 순)에서 서로 차단 관계가 없는 want명 묶음을 고른다.
    want명이 모이면 바로 반환한다.
    """
    for i in range(len(members)):
        batch = [members[i]]
        for cand in members[i + 1:]:
            if len(batch) == want:
                break
            if all((cand[0], b[0]) not in pairs for b in batch):
                batch.append(cand)
        if len(batch) == want:
            return batch
    return None


def try_match():
    """같은 (출발역, 도착 대학)을 고른 대기자끼리 방을 만든다."""
    created = []
    with waiting_lock:
        if len(waiting) < MIN_PEOPLE:
            return
        pairs = load_block_pairs()
        groups = {}
        for uid, w in waiting.items():
            groups.setdefault((w["origin"], w["dest"], w["want"]), []).append((uid, w["since"]))

        for (origin, dest, want), members in groups.items():
            members.sort(key=lambda m: m[1])  # 오래 기다린 순
            while len(members) >= want:
                batch = pick_batch(members, pairs, want)
                if not batch:
                    break
                ids = [uid for uid, _ in batch]
                members = [m for m in members if m[0] not in ids]
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
            return {"waiting": False, "count": 0, "elapsed": 0, "origin": None, "dest": None, "want": None}
        same_route = sum(
            1 for x in waiting.values()
            if x["origin"] == w["origin"] and x["dest"] == w["dest"] and x["want"] == w["want"]
        )
        return {
            "waiting": True,
            "count": same_route,
            "elapsed": int(time.time() - w["since"]),
            "origin": w["origin"],
            "dest": w["dest"],
            "want": w["want"],
        }


# ──────────────── 페이지 ────────────────
@app.get("/")
def index():
    cfg = {
        "name": APP_NAME,
        "min": MIN_PEOPLE,
        "max": MAX_PEOPLE,
        "wait": MATCH_WAIT_SECONDS,
        "reasons": REPORT_REASONS,
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
    """회원가입 / 닉네임 변경 화면의 '중복확인' 버튼용. 쓸 수 있으면 available=True."""
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
        me_row = current_user()  # 로그인한 상태에서 본인 닉네임을 확인하면 '사용 가능'으로 봐요
        err = nickname_error(value, exclude_uid=me_row["id"] if me_row else None)
        if err:
            return jsonify(available=False, message=err)
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


# ──────────────── API: 마이페이지 ────────────────
@app.post("/api/me/nickname")
@login_required
def change_nickname(user):
    nickname = ((request.get_json(silent=True) or {}).get("nickname") or "").strip()
    err = nickname_error(nickname, exclude_uid=user["id"])
    if err:
        return jsonify(error=err), 400
    try:
        run("UPDATE users SET nickname=? WHERE id=?", (nickname, user["id"]), write=True)
    except sqlite3.IntegrityError:
        return jsonify(error="이미 사용 중인 닉네임이에요."), 409
    return jsonify(ok=True, nickname=nickname)


@app.post("/api/me/password")
@login_required
def change_password(user):
    d = request.get_json(silent=True) or {}
    if not check_password_hash(user["pw_hash"], d.get("current") or ""):
        return jsonify(error="현재 비밀번호가 맞지 않아요."), 400
    new = d.get("new") or ""
    if len(new) < 8:
        return jsonify(error="새 비밀번호는 8자 이상이어야 해요."), 400
    run("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), user["id"]), write=True)
    return jsonify(ok=True)


@app.post("/api/me/delete")
@login_required
def delete_account(user):
    d = request.get_json(silent=True) or {}
    if not check_password_hash(user["pw_hash"], d.get("password") or ""):
        return jsonify(error="비밀번호가 맞지 않아요."), 400
    uid = user["id"]
    with waiting_lock:
        waiting.pop(uid, None)
    rid = active_room_id(uid)
    if rid:
        leave_room_now(uid, user["nickname"], rid)
    # 대화 기록 보존을 위해 행은 남기고, 개인 정보만 지워요. 이 계정으로는 다시 로그인할 수 없어요.
    run(
        "UPDATE users SET username=?, nickname=?, pw_hash=? WHERE id=?",
        (f"deleted_{uid}", f"탈퇴회원{uid}", generate_password_hash(secrets.token_hex(16)), uid),
        write=True,
    )
    run("DELETE FROM blocks WHERE blocker_id=?", (uid,), write=True)
    session.pop("uid", None)
    return jsonify(ok=True)


@app.get("/api/history")
@login_required
def history(user):
    rows = run(
        "SELECT r.id, r.origin, r.dest, r.created_at, r.closed_at, r.fare_total, r.fare_per, "
        "r.fare_people, rm.left_at "
        "FROM room_members rm JOIN rooms r ON r.id = rm.room_id "
        "WHERE rm.user_id=? ORDER BY r.id DESC LIMIT 30",
        (user["id"],),
    )
    blocked = {r["blocked_id"] for r in run("SELECT blocked_id FROM blocks WHERE blocker_id=?", (user["id"],))}
    out = []
    for r in rows:
        others = run(
            "SELECT u.id, u.nickname FROM room_members m JOIN users u ON u.id = m.user_id "
            "WHERE m.room_id=? AND m.user_id != ? ORDER BY u.id",
            (r["id"], user["id"]),
        )
        out.append({
            "id": r["id"], "origin": r["origin"], "dest": r["dest"], "created_at": r["created_at"],
            "active": r["left_at"] is None and r["closed_at"] is None,
            "fare_total": r["fare_total"], "fare_per": r["fare_per"], "fare_people": r["fare_people"],
            "members": [{"id": o["id"], "nickname": o["nickname"], "blocked": o["id"] in blocked} for o in others],
        })
    # 절약 금액: 정산이 기록된 모든 이용에서 (혼자 탔다면 낸 택시비 전액) - (실제 내 부담금)
    srows = run(
        "SELECT r.fare_total, r.fare_per FROM room_members rm JOIN rooms r ON r.id = rm.room_id "
        "WHERE rm.user_id=? AND r.fare_total IS NOT NULL AND r.fare_per IS NOT NULL AND r.fare_people >= 2",
        (user["id"],),
    )
    alone = sum(r["fare_total"] for r in srows)
    paid = sum(min(r["fare_per"], r["fare_total"]) for r in srows)
    savings = {"count": len(srows), "alone": alone, "paid": paid, "saved": max(alone - paid, 0)}
    return jsonify(history=out, savings=savings)


# ──────────────── API: 신고 / 차단 ────────────────
@app.get("/api/blocks")
@login_required
def list_blocks(user):
    rows = run(
        "SELECT u.id, u.nickname FROM blocks b JOIN users u ON u.id = b.blocked_id "
        "WHERE b.blocker_id=? ORDER BY b.created_at DESC",
        (user["id"],),
    )
    return jsonify(blocks=[{"id": r["id"], "nickname": r["nickname"]} for r in rows])


def _target_id(d):
    try:
        return int(d.get("target_id"))
    except (TypeError, ValueError):
        return None


@app.post("/api/block")
@login_required
def block_user(user):
    target = _target_id(request.get_json(silent=True) or {})
    if not target or target == user["id"]:
        return jsonify(error="차단할 수 없는 대상이에요."), 400
    if not shared_room(user["id"], target):
        return jsonify(error="같이 채팅한 적이 있는 사람만 차단할 수 있어요."), 403
    run(
        "INSERT OR IGNORE INTO blocks(blocker_id, blocked_id, created_at) VALUES (?,?,?)",
        (user["id"], target, now()), write=True,
    )
    return jsonify(ok=True)


@app.post("/api/unblock")
@login_required
def unblock_user(user):
    target = _target_id(request.get_json(silent=True) or {})
    if not target:
        return jsonify(error="잘못된 요청이에요."), 400
    run("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?", (user["id"], target), write=True)
    return jsonify(ok=True)


@app.post("/api/report")
@login_required
def report_user(user):
    d = request.get_json(silent=True) or {}
    target = _target_id(d)
    reason = d.get("reason")
    detail = str(d.get("detail") or "").strip()[:300]
    try:
        rid = int(d.get("room_id"))
    except (TypeError, ValueError):
        rid = None

    if not target or target == user["id"] or not rid:
        return jsonify(error="신고할 수 없는 대상이에요."), 400
    if reason not in REPORT_REASONS:
        return jsonify(error="신고 사유를 선택해주세요."), 400
    both_in_room = run(
        "SELECT COUNT(*) AS c FROM room_members WHERE room_id=? AND user_id IN (?,?)",
        (rid, user["id"], target), one=True,
    )["c"] == 2
    if not both_in_room:
        return jsonify(error="같은 채팅방에 있었던 사람만 신고할 수 있어요."), 403
    if run(
        "SELECT 1 FROM reports WHERE reporter_id=? AND target_id=? AND room_id=?",
        (user["id"], target, rid), one=True,
    ):
        return jsonify(error="이미 신고한 사용자예요."), 409

    run(
        "INSERT INTO reports(reporter_id, target_id, room_id, reason, detail, created_at) VALUES (?,?,?,?,?,?)",
        (user["id"], target, rid, reason, detail, now()), write=True,
    )
    if d.get("also_block"):
        run(
            "INSERT OR IGNORE INTO blocks(blocker_id, blocked_id, created_at) VALUES (?,?,?)",
            (user["id"], target, now()), write=True,
        )
    return jsonify(ok=True)


@app.get("/api/admin/reports")
def admin_reports():
    """ADMIN_KEY 환경변수를 설정한 경우에만 열려요. 요청 헤더 X-Admin-Key 로 확인해요."""
    key = request.headers.get("X-Admin-Key", "")
    if not ADMIN_KEY or not hmac.compare_digest(key, ADMIN_KEY):
        return jsonify(error="권한이 없어요."), 403
    rows = run(
        "SELECT r.id, r.room_id, r.reason, r.detail, r.created_at, "
        "a.nickname AS reporter, b.nickname AS target "
        "FROM reports r JOIN users a ON a.id = r.reporter_id JOIN users b ON b.id = r.target_id "
        "ORDER BY r.id DESC LIMIT 100"
    )
    return jsonify(reports=[dict(r) for r in rows])


# ──────────────── API: 매칭 ────────────────
@app.get("/api/estimate")
def estimate():
    origin, dest = request.args.get("origin"), request.args.get("dest")
    if origin not in ALL_STATIONS or dest not in ALL_UNIVERSITIES:
        return jsonify(estimate=None)
    return jsonify(estimate=estimate_fare(origin, dest))


@app.post("/api/queue/join")
@login_required
def queue_join(user):
    d = request.get_json(silent=True) or {}
    origin, dest = d.get("origin"), d.get("dest")
    if origin not in ALL_STATIONS:
        return jsonify(error="출발역을 선택해주세요."), 400
    if dest not in ALL_UNIVERSITIES:
        return jsonify(error="도착 대학을 선택해주세요."), 400
    try:
        want = int(d.get("want", MAX_PEOPLE))
    except (TypeError, ValueError):
        want = 0
    if not (MIN_PEOPLE <= want <= MAX_PEOPLE):
        return jsonify(error=f"인원은 {MIN_PEOPLE}~{MAX_PEOPLE}명 중에서 골라주세요."), 400
    if active_room_id(user["id"]):
        return jsonify(error="이미 참여 중인 채팅방이 있어요."), 409

    with waiting_lock:
        w = waiting.get(user["id"])
        if not w or (w["origin"], w["dest"], w["want"]) != (origin, dest, want):
            waiting[user["id"]] = {"since": time.time(), "origin": origin, "dest": dest, "want": want}
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
    blocked = [r["blocked_id"] for r in run("SELECT blocked_id FROM blocks WHERE blocker_id=?", (user["id"],))]
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
        if r["user_id"] not in blocked  # 내가 차단한 사람의 메시지는 보이지 않아요
    ]
    return jsonify(
        room_id=rid, origin=room["origin"], dest=room["dest"],
        members=members_of(rid), messages=messages, blocked=blocked,
        state=room_state(rid), estimate=estimate_fare(room["origin"], room["dest"]),
    )


@app.post("/api/room/<int:rid>/leave")
@login_required
def room_leave(user, rid):
    if not is_member(user["id"], rid):
        return jsonify(ok=True)
    leave_room_now(user["id"], user["nickname"], rid)
    return jsonify(ok=True)


@app.post("/api/room/<int:rid>/meet")
@login_required
def room_meet(user, rid):
    """만날 장소(와 시간)를 정해서 모두에게 공유."""
    if not is_member(user["id"], rid):
        return jsonify(error="참여 중인 방이 아니에요."), 403
    d = request.get_json(silent=True) or {}
    place = str(d.get("place") or "").strip()[:40]
    t = str(d.get("time") or "").strip()
    if not place:
        return jsonify(error="만날 장소를 입력해주세요."), 400
    if t and not TIME_RE.match(t):
        return jsonify(error="시간 형식이 맞지 않아요."), 400
    run(
        "UPDATE rooms SET meet_place=?, meet_time=?, meet_by=? WHERE id=?",
        (place, t or None, user["id"], rid), write=True,
    )
    post_system(rid, f"{user['nickname']}님이 만날 장소를 정했어요: {place}" + (f" ({t})" if t else ""))
    broadcast_state(rid)
    return jsonify(ok=True, state=room_state(rid))


@app.post("/api/room/<int:rid>/fare")
@login_required
def room_fare(user, rid):
    """택시비를 입력하면 지금 방에 있는 인원수로 나눠서 모두에게 보여줘요. (결제한 사람 = 입력한 사람)"""
    if not is_member(user["id"], rid):
        return jsonify(error="참여 중인 방이 아니에요."), 403
    try:
        total = int((request.get_json(silent=True) or {}).get("total"))
    except (TypeError, ValueError):
        return jsonify(error="택시비를 숫자로 입력해주세요."), 400
    if not FARE_MIN <= total <= FARE_MAX:
        return jsonify(error=f"택시비는 {FARE_MIN:,}원 ~ {FARE_MAX:,}원 사이로 입력해주세요."), 400

    people = len(members_of(rid))
    per = -(-total // people)              # 올림
    per = -(-per // 10) * 10               # 10원 단위로 올림
    run(
        "UPDATE rooms SET fare_total=?, fare_payer=?, fare_people=?, fare_per=? WHERE id=?",
        (total, user["id"], people, per, rid), write=True,
    )
    post_system(
        rid,
        f"{user['nickname']}님이 택시비 {total:,}원을 결제했어요. {people}명이 나누면 1인당 {per:,}원이에요. "
        f"{user['nickname']}님께 보내주세요.",
    )
    broadcast_state(rid)
    return jsonify(ok=True, per=per, people=people, state=room_state(rid))


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


# 서버를 켤 때마다 DB 준비 (python app.py 로 실행하든, 다른 서버로 실행하든 동일)
init_db()

if __name__ == "__main__":
    socketio.start_background_task(matcher_loop)
    # 배포 서비스(Render 등)는 PORT 환경변수로 포트를 알려줘요. 내 컴퓨터에서는 5000번을 써요.
    port = int(os.environ.get("PORT", "5000"))
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True, use_reloader=False)
