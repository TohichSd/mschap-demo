from __future__ import annotations
import base64
import logging
import os
import uuid
from typing import Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from db import Database
from mschap import MSCHAPv2


# ЛОГИРОВАНИЕ

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("mschap-server")
log.info("=== Starting MS-CHAPv2 Server ===")


# СЕССИИ АУТЕНТИФИКАЦИИ


class AuthSession:
    """
    Состояние одной MS-CHAPv2-сессии на сервере.
    """
    def __init__(self, username: str, auth_challenge: bytes):
        self.username = username
        self.auth_challenge = auth_challenge  # 16 байт


class AuthSessionManager:
    """
    ООП-класс для хранения сессий MS-CHAPv2.
    """
    def __init__(self):
        self._sessions: Dict[str, AuthSession] = {}

    def create_session(self, username: str) -> str:
        import os
        auth_challenge = os.urandom(16)  # просто случайный challenge
        session_id = str(uuid.uuid4())
        self._sessions[session_id] = AuthSession(username, auth_challenge)
        log.info("[CHALLENGE] New session: %s for user '%s'", session_id, username)
        return session_id

    def get_session(self, session_id: str) -> AuthSession:
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError("session not found")
        return sess

    def get_auth_challenge(self, session_id: str) -> bytes:
        return self.get_session(session_id).auth_challenge

    def get_username(self, session_id: str) -> str:
        return self.get_session(session_id).username

    def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        log.info("[CHALLENGE] Session %s deleted", session_id)



# Pydantic DTO


class RegisterRequest(BaseModel):
    username: str
    password: str


class RegisterResult(BaseModel):
    success: bool


class ChallengeRequest(BaseModel):
    username: str


class ChallengeResponse(BaseModel):
    session_id: str
    auth_challenge: str  # base64


class AuthResponseRequest(BaseModel):
    session_id: str
    username: str
    peer_challenge: str   # base64 (16 bytes)
    nt_response: str      # base64 (24 bytes)


class AuthResult(BaseModel):
    success: bool



# ИНИЦИАЛИЗАЦИЯ БД И СЕРВЕРА


db = Database()
try:
    db.init_db()
    log.info("DB initialized successfully (tables created if needed).")
except Exception as e:
    log.error("DB initialization failed: %s", e)
    raise

session_manager = AuthSessionManager()
app = FastAPI(title="MS-CHAPv2 Demo Server")



# ЭНДПОИНТ: РЕГИСТРАЦИЯ


@app.post("/auth/register", response_model=RegisterResult)
def register(req: RegisterRequest) -> RegisterResult:
    log.info("[REGISTER] Request: username='%s'", req.username)

    user = db.get_user_by_username(req.username)
    if user:
        log.warning("[REGISTER] User already exists: '%s'", req.username)
        raise HTTPException(status_code=400, detail="User already exists")

    nt_hash = MSCHAPv2.nt_password_hash(req.password)
    try:
        new_user = db.create_user(req.username, nt_hash)
        log.info("[REGISTER] Created user id=%s username='%s'", new_user.id, new_user.username)
    except Exception as e:
        log.error("[REGISTER] DB error: %s", e)
        raise HTTPException(status_code=500, detail="DB error")

    return RegisterResult(success=True)



# ЭНДПОИНТ: ВЫДАЧА CHALLENGE


@app.post("/auth/challenge", response_model=ChallengeResponse)
def auth_challenge(req: ChallengeRequest) -> ChallengeResponse:
    log.info("[CHALLENGE] Request: username='%s'", req.username)

    user = db.get_user_by_username(req.username)
    if not user:
        log.warning("[CHALLENGE] User not found: '%s'", req.username)
        raise HTTPException(status_code=404, detail="User not found")

    session_id = session_manager.create_session(req.username)
    auth_challenge = session_manager.get_auth_challenge(session_id)

    auth_b64 = base64.b64encode(auth_challenge).decode("ascii")
    log.info("[CHALLENGE] session_id=%s auth_challenge=%s", session_id, auth_b64)

    return ChallengeResponse(
        session_id=session_id,
        auth_challenge=auth_b64,
    )



# ЭНДПОИНТ: ПРОВЕРКА NT-RESPONSE


@app.post("/auth/response", response_model=AuthResult)
def auth_response(req: AuthResponseRequest) -> AuthResult:
    log.info("[AUTH] Response: session_id=%s username='%s'", req.session_id, req.username)

    # сессия
    try:
        sess_username = session_manager.get_username(req.session_id)
        auth_challenge = session_manager.get_auth_challenge(req.session_id)
    except KeyError:
        log.error("[AUTH] Invalid session_id: %s", req.session_id)
        raise HTTPException(status_code=400, detail="Invalid session_id")

    if sess_username != req.username:
        log.error("[AUTH] Username mismatch: expected '%s', got '%s'", sess_username, req.username)
        raise HTTPException(status_code=400, detail="Username mismatch")

    # декодируем данные клиента
    try:
        peer_challenge = base64.b64decode(req.peer_challenge)
        nt_response = base64.b64decode(req.nt_response)
    except Exception:
        log.error("[AUTH] Failed to decode base64 in request")
        raise HTTPException(status_code=400, detail="Bad base64")

    if len(peer_challenge) != 16 or len(nt_response) != 24:
        log.error("[AUTH] Wrong lengths: peer_challenge=%d, nt_response=%d",
                  len(peer_challenge), len(nt_response))
        raise HTTPException(status_code=400, detail="Wrong lengths")

    # достаём NT-хеш пользователя
    user = db.get_user_by_username(req.username)
    if not user:
        log.error("[AUTH] User '%s' not found in DB during auth", req.username)
        raise HTTPException(status_code=404, detail="User not found")

    stored_nt_hash = user.nt_hash
    log.info("[AUTH] Verifying NT-Response for user '%s'...", req.username)

    ok = MSCHAPv2.verify_nt_response(
        auth_challenge=auth_challenge,
        peer_challenge=peer_challenge,
        username=req.username,
        stored_nt_hash=stored_nt_hash,
        received_nt_response=nt_response,
    )

    # заканчиваем сессию
    session_manager.delete_session(req.session_id)

    if ok:
        log.info("[AUTH] SUCCESS for user '%s'", req.username)
    else:
        log.warning("[AUTH] FAILED for user '%s'", req.username)

    return AuthResult(success=ok)



# ЛОКАЛЬНЫЙ ЗАПУСК (через python server.py)


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("SERVER_PORT", "8000"))

    log.info("Running MS-CHAPv2 server on http://%s:%d ...", host, port)
    uvicorn.run("server:app", host=host, port=port, reload=False)
