import base64
import binascii
import hashlib
import hmac
import re
import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from database import get_db, now

router = APIRouter(tags=["users"])


# ---------- passwords & auth ----------

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, digest = stored.split("$", 1)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return hmac.compare_digest(candidate, digest)


def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not logged in")
    token = authorization[7:].strip()
    with get_db() as db:
        row = db.execute(
            "SELECT u.id, u.name, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ?",
            (token,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return {**dict(row), "token": token}


# ---------- avatars ----------

MAX_AVATAR_BYTES = 500_000
DATA_URL_RE = re.compile(r"^data:(image/(?:png|jpeg|webp|gif));base64,(.+)$", re.S)


def decode_avatar(data_url: str):
    match = DATA_URL_RE.match(data_url)
    if not match:
        raise HTTPException(status_code=422, detail="Avatar must be a PNG, JPEG, WebP or GIF image")
    try:
        data = base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=422, detail="Avatar image data is corrupted")
    if len(data) > MAX_AVATAR_BYTES:
        raise HTTPException(status_code=413, detail="Avatar image is too large (max 500 KB)")
    return match.group(1), data


# Ready-made faces users can pick instead of uploading (Unsplash photo ids)
AVATAR_PRESETS = [
    "1534528741775-53994a69daeb", "1500648767791-00dcc994a43e", "1494790108377-be9c29b29330",
    "1507003211169-0a1dd7228f2d", "1438761681033-6461ffad8d80", "1472099645785-5658abf4ff4e",
    "1544005313-94ddf0286df2", "1506794778202-cad84cf45f1d", "1517841905240-472988babdf9",
    "1539571696357-5a69c17a67c6",
]


def preset_url(preset: str, size: int = 256) -> str:
    return f"https://images.unsplash.com/photo-{preset}?w={size}&h={size}&fit=crop&crop=faces&q=80"


def check_preset(preset: str) -> str:
    if preset not in AVATAR_PRESETS:
        raise HTTPException(status_code=422, detail="Unknown avatar preset")
    return preset


# ---------- models ----------

AvatarField = Field(None, max_length=700_000, description="Uploaded image as a data URL (data:image/...;base64,...)")
PresetField = Field(None, description="Id of a ready-made face from GET /avatars")


class Credentials(BaseModel):
    name: str = Field(..., min_length=2, max_length=30)
    password: str = Field(..., min_length=4, max_length=128)


class UserCreate(Credentials):
    avatar: Optional[str] = AvatarField
    avatar_preset: Optional[str] = PresetField


class UserPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=30)
    password: Optional[str] = Field(None, min_length=4, max_length=128)
    avatar: Optional[str] = AvatarField
    avatar_preset: Optional[str] = PresetField


class AvatarPreset(BaseModel):
    id: str
    url: str


class User(BaseModel):
    id: int
    name: str
    created_at: str
    has_avatar: bool


class LoginResult(BaseModel):
    token: str
    user: User


# ---------- helpers ----------

USER_COLUMNS = "id, name, created_at, (avatar IS NOT NULL OR avatar_preset IS NOT NULL) AS has_avatar"


def fetch_user(db, user_id: int) -> User:
    row = db.execute(f"SELECT {USER_COLUMNS} FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return User(**dict(row))


def require_self(me: dict, user_id: int):
    if me["id"] != user_id:
        raise HTTPException(status_code=403, detail="You can only modify your own account")


def save_user(db, user_id: int, fields: dict):
    if "name" in fields:
        taken = db.execute(
            "SELECT 1 FROM users WHERE name = ? AND id != ?", (fields["name"], user_id)
        ).fetchone()
        if taken:
            raise HTTPException(status_code=409, detail="That name is already taken")
        db.execute("UPDATE users SET name = ? WHERE id = ?", (fields["name"], user_id))
        db.execute("UPDATE messages SET sender = ? WHERE user_id = ?", (fields["name"], user_id))
    if "password" in fields:
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(fields["password"]), user_id),
        )
    if fields.get("avatar"):
        mime, data = decode_avatar(fields["avatar"])
        db.execute(
            "UPDATE users SET avatar = ?, avatar_type = ?, avatar_preset = NULL WHERE id = ?",
            (data, mime, user_id),
        )
    elif fields.get("avatar_preset"):
        db.execute(
            "UPDATE users SET avatar = NULL, avatar_type = NULL, avatar_preset = ? WHERE id = ?",
            (check_preset(fields["avatar_preset"]), user_id),
        )


# ---------- /avatars ----------

@router.get("/avatars", response_model=List[AvatarPreset])
def list_avatar_presets():
    return [AvatarPreset(id=p, url=preset_url(p)) for p in AVATAR_PRESETS]


# ---------- /users ----------

@router.get("/users", response_model=List[User])
def list_users():
    with get_db() as db:
        rows = db.execute(f"SELECT {USER_COLUMNS} FROM users ORDER BY id").fetchall()
        return [User(**dict(r)) for r in rows]


@router.get("/users/me", response_model=User)
def get_me(me: dict = Depends(current_user)):
    with get_db() as db:
        return fetch_user(db, me["id"])


@router.get("/users/{user_id}/avatar")
def get_avatar(user_id: int, if_none_match: Optional[str] = Header(None)):
    with get_db() as db:
        row = db.execute(
            "SELECT avatar, avatar_type, avatar_preset FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if row is not None and row["avatar"] is None and row["avatar_preset"]:
        return RedirectResponse(preset_url(row["avatar_preset"]), headers={"Cache-Control": "no-cache"})
    if row is None or row["avatar"] is None:
        raise HTTPException(status_code=404, detail="No avatar")
    etag = '"' + hashlib.sha1(row["avatar"]).hexdigest() + '"'
    headers = {"ETag": etag, "Cache-Control": "no-cache"}
    if if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return Response(content=row["avatar"], media_type=row["avatar_type"], headers=headers)


@router.get("/users/{user_id}", response_model=User)
def get_user(user_id: int):
    with get_db() as db:
        return fetch_user(db, user_id)


@router.post("/users", response_model=User, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate):
    name = user.name.strip()
    mime, data = decode_avatar(user.avatar) if user.avatar else (None, None)
    preset = check_preset(user.avatar_preset) if user.avatar_preset and not data else None
    with get_db() as db:
        if db.execute("SELECT 1 FROM users WHERE name = ?", (name,)).fetchone():
            raise HTTPException(status_code=409, detail="That name is already taken")
        cur = db.execute(
            "INSERT INTO users (name, password_hash, created_at, avatar, avatar_type, avatar_preset) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, hash_password(user.password), now(), data, mime, preset),
        )
        return fetch_user(db, cur.lastrowid)


@router.put("/users/{user_id}", response_model=User)
def replace_user(user_id: int, user: UserCreate, me: dict = Depends(current_user)):
    require_self(me, user_id)
    with get_db() as db:
        save_user(db, user_id, {"name": user.name.strip(), "password": user.password})
        db.execute(
            "UPDATE users SET avatar = NULL, avatar_type = NULL, avatar_preset = NULL WHERE id = ?",
            (user_id,),
        )
        save_user(db, user_id, {"avatar": user.avatar, "avatar_preset": user.avatar_preset})
        return fetch_user(db, user_id)


@router.patch("/users/{user_id}", response_model=User)
def update_user(user_id: int, user: UserPatch, me: dict = Depends(current_user)):
    require_self(me, user_id)
    fields = user.model_dump(exclude_unset=True, exclude_none=True)
    if "name" in fields:
        fields["name"] = fields["name"].strip()
    with get_db() as db:
        save_user(db, user_id, fields)
        return fetch_user(db, user_id)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, me: dict = Depends(current_user)):
    require_self(me, user_id)
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.head("/users/{user_id}")
def head_user(user_id: int):
    with get_db() as db:
        fetch_user(db, user_id)
    return Response(status_code=status.HTTP_200_OK)


# ---------- login / logout ----------

@router.post("/login", response_model=LoginResult)
def login(credentials: Credentials):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE name = ?", (credentials.name.strip(),)
        ).fetchone()
        if row is None or not verify_password(credentials.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Wrong name or password")
        token = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, row["id"], now()),
        )
        return LoginResult(token=token, user=fetch_user(db, row["id"]))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(me: dict = Depends(current_user)):
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE token = ?", (me["token"],))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
