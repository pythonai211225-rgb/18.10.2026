from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from database import get_db, now
from users import current_user

router = APIRouter(tags=["messages"])


class MessageCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=2000)


class MessagePatch(BaseModel):
    content: Optional[str] = Field(None, min_length=1, max_length=2000)


class Message(BaseModel):
    id: int
    user_id: Optional[int]
    sender: str
    content: str
    created_at: str
    updated_at: str


def fetch_message(db, message_id: int) -> Message:
    row = db.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Message not found")
    return Message(**dict(row))


def fetch_own_message(db, message_id: int, me: dict) -> Message:
    msg = fetch_message(db, message_id)
    if msg.user_id != me["id"]:
        raise HTTPException(status_code=403, detail="You can only change your own messages")
    return msg


@router.get("/messages", response_model=List[Message])
def list_messages(
    sender: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    sql, params = "SELECT * FROM messages", []
    if sender:
        sql += " WHERE sender = ?"
        params.append(sender)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    with get_db() as db:
        return [Message(**dict(r)) for r in db.execute(sql, params).fetchall()]


@router.get("/messages/{message_id}", response_model=Message)
def get_message(message_id: int):
    with get_db() as db:
        return fetch_message(db, message_id)


@router.post("/messages", response_model=Message, status_code=status.HTTP_201_CREATED)
def create_message(msg: MessageCreate, me: dict = Depends(current_user)):
    ts = now()
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO messages (user_id, sender, content, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (me["id"], me["name"], msg.content, ts, ts),
        )
        return fetch_message(db, cur.lastrowid)


@router.put("/messages/{message_id}", response_model=Message)
def replace_message(message_id: int, msg: MessageCreate, me: dict = Depends(current_user)):
    with get_db() as db:
        fetch_own_message(db, message_id, me)
        db.execute(
            "UPDATE messages SET content = ?, updated_at = ? WHERE id = ?",
            (msg.content, now(), message_id),
        )
        return fetch_message(db, message_id)


@router.patch("/messages/{message_id}", response_model=Message)
def update_message(message_id: int, msg: MessagePatch, me: dict = Depends(current_user)):
    fields = msg.model_dump(exclude_unset=True, exclude_none=True)
    with get_db() as db:
        fetch_own_message(db, message_id, me)
        if fields:
            db.execute(
                "UPDATE messages SET content = ?, updated_at = ? WHERE id = ?",
                (fields["content"], now(), message_id),
            )
        return fetch_message(db, message_id)


@router.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_message(message_id: int, me: dict = Depends(current_user)):
    with get_db() as db:
        fetch_own_message(db, message_id, me)
        db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.head("/messages/{message_id}")
def head_message(message_id: int):
    with get_db() as db:
        fetch_message(db, message_id)
    return Response(status_code=status.HTTP_200_OK)
