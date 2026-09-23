from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg
from pwdlib import PasswordHash

app = FastAPI(
    root_path="/api"
)

password_hash = PasswordHash.recommended()

conn = psycopg.connect(
    host="100.125.8.79",
    port=5432,
    dbname="platform-db",
    user="db_user",
    password="20mp10gc-DB"
)

def hash_password(password: str) -> str:
    return password_hash.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)

@app.get("/")
def home():
    return {"message": "online"}

class User(BaseModel):
    username: str
    password: str

class TokenCheck(BaseModel):
    username: str
    token: str

class LogoutRequest(BaseModel):
    token: str

class GetUsersRequest(BaseModel):
    username: str
    token: str

class GetRoleRequest(BaseModel):
    username: str
    token: str

@app.post("/register", status_code=201)
def register(user: User):
    username = user.username
    password = user.password
    passwordHash = hash_password(password)
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO users (username, passwordhash) VALUES (%s, %s)", (username, passwordHash))
            conn.commit()
    except psycopg.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )
    return {"status": "success", "message": "User registered successfully."}

@app.post("/login")
def login(user: User):
    username = user.username
    password = user.password
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (username,))
        uuid = cur.fetchone()
        if uuid:
            cur.execute("SELECT passwordhash FROM users WHERE username = %s", (username,))
            stored_password_hash = cur.fetchone()
            if stored_password_hash:
                if verify_password(password, stored_password_hash[0]):
                    cur.execute("INSERT INTO logins (useruuid) VALUES (%s) RETURNING token", (uuid[0],))
                    login_info = cur.fetchone()
                    conn.commit()
                    if login_info:
                        return {"status": "success", "token": login_info[0]}
                    else:
                        conn.rollback()
                        raise HTTPException(
                            status_code=500,
                            detail="Failed to create login session"
                        )
                else:
                    raise HTTPException(
                        status_code=401,
                        detail="Incorrect password"
                    )
        else:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )


@app.post("/logout")
def logout(data: LogoutRequest):
    token = data.token
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Token is required"
        )
    with conn.cursor() as cur:
        cur.execute("DELETE FROM logins WHERE token = %s", (token,))
        deleted_rows = cur.rowcount
        conn.commit()
        if deleted_rows > 0:
            return {"status": "success", "message": "Logged out successfully."}
        else:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )


@app.post("/check_token")
def check_token(data: TokenCheck):
    username = data.username
    token = data.token
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Token is required"
        )
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (username,))
        user_uuid = cur.fetchone()
        if user_uuid:
            cur.execute("SELECT token FROM logins WHERE useruuid = %s AND token = %s", (user_uuid[0], token))
            token_info = cur.fetchone()
            if token_info:
                return {"status": "success", "message": "Token is valid."}
            else:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid token"
                )
        else:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )


@app.post("/get_users")
def get_users(data: GetUsersRequest):
    username = data.username
    token = data.token
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (username,))
        user_uuid = cur.fetchone()
        if user_uuid:
            cur.execute("SELECT token FROM logins WHERE useruuid = %s AND token = %s", (user_uuid[0], token))
            token_info = cur.fetchone()
            if token_info:
                cur.execute("SELECT role FROM users WHERE useruuid = %s", (user_uuid[0],))
                role = cur.fetchone()
                if role:
                    if role[0] == "ADMIN":
                        cur.execute("SELECT * FROM users")
                        users = cur.fetchall()
                        if users:
                            return{"status": "success", "users": users}
                        else:
                            raise HTTPException(
                                status_code=500,
                                detail="Users not found"
                            )
                    else:
                        raise HTTPException(
                            status_code=403,
                            detail="Access denied; required permission is missing."
                        )
                else:
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
            else:
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )


@app.post("/get_role")
def get_role(data: GetRoleRequest):
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (data.username,))
        user_uuid=cur.fetchone()
        if user_uuid:
            cur.execute("SELECT token FROM logins WHERE useruuid = %s and token = %s", (user_uuid[0], data.token,))
            token_info=cur.fetchone()
            if token_info:
                cur.execute("SELECT role FROM users WHERE useruuid = %s", (user_uuid[0],))
                role = cur.fetchone()
                if role:
                    return{"status": "success", "role": role[0]}
                else:
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
            else:
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )