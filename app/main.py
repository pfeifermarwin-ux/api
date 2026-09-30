from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, Field
import psycopg
from pwdlib import PasswordHash
from datetime import date, datetime
from uuid import UUID
from psycopg.types.json import Jsonb

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

def log(useruuid, level, message, path, status_code, metadata):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO logs (useruuid, level, message, path, status_code, metadata) VALUES (%s, %s, %s, %s, %s, %s)", (useruuid, level, message, path, status_code, Jsonb(metadata) if metadata is not None else None))
        conn.commit()

@app.get("/")
def home():
    return {"message": "online"}

class RegisterRequest(BaseModel):
    username: str
    password: str
    name: str
    email: EmailStr
    birthdate: date

class LoginRequest(BaseModel):
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

class GetUserInfoRequest(BaseModel):
    useruuid: str
    requestUserName: str
    requestUserToken: str

class UserInfoResponse(BaseModel):
    status: str
    username: str
    useruuid: UUID
    createdat: datetime
    role: str
    lastlogin: datetime | None = None
    name: str
    email: str
    birthdate: date

@app.post("/register",)
def register(user: RegisterRequest):
    username = user.username
    password = user.password
    name = user.name
    email = user.email
    birthdate = user.birthdate
    passwordHash = hash_password(password)
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO users (username, passwordhash, name, email, birthdate) VALUES (%s, %s, %s, %s, %s)", (username, passwordHash, name, email, birthdate))
            conn.commit()
    except psycopg.errors.UniqueViolation:
        conn.rollback()
        log(None, "WARNING", "Username or Email already exists", "/register", 409, user.model_dump(exclude={"password"}))
        raise HTTPException(
            status_code=409,
            detail="Username or Email already exists"
        )
    log(None, "INFO", "User registered successfully", "/register", 200, user.model_dump(exclude={"password"}))
    return {"status": "success", "message": "User registered successfully."}

@app.post("/login")
def login(user: LoginRequest):
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
                    cur.execute("UPDATE users SET lastlogin = NOW() WHERE useruuid = %s",(uuid[0],))
                    conn.commit()
                    if login_info:
                        log(uuid[0], "INFO", "User Login successfull", "/login", 200, user.model_dump(exclude={"password"}))
                        return {"status": "success", "token": login_info[0]}
                    else:
                        log(uuid[0], "ERROR", "Failed to create login session", "/login", 401, user.model_dump(exclude={"password"}))
                        conn.rollback()
                        raise HTTPException(
                            status_code=500,
                            detail="Failed to create login session"
                        )
                else:
                    log(uuid[0], "WARNING", "Incorrect password", "/login", 401, user.model_dump(exclude={"password"}))
                    raise HTTPException(
                        status_code=401,
                        detail="Incorrect password"
                    )
        else:
            log(None, "WARNING", "User not found", "/login", 404, user.model_dump(exclude={"password"}))
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )


@app.post("/logout")
def logout(data: LogoutRequest):
    token = data.token
    if not token:
        log(None, "WARNING", "Logout Request without Token", "/logout", 401, data.model_dump())
        raise HTTPException(
            status_code=401,
            detail="Token is required"
        )
    with conn.cursor() as cur:
        cur.execute("DELETE FROM logins WHERE token = %s", (token,))
        deleted_rows = cur.rowcount
        conn.commit()
        if deleted_rows > 0:
            log(None, "WARNING", "Logged out successfully", "/logout", 200, data.model_dump())
            return {"status": "success", "message": "Logged out successfully."}
        else:
            log(None, "WARNING", "Logout Request with Invalid token", "/logout", 401, data.model_dump())
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
                        cur.execute("SELECT username, useruuid, createdat, role FROM users")
                        users = [
                            {
                                "username": row[0],
                                "useruuid": row[1],
                                "createdat": row[2],
                                "role": row[3]
                            }
                            for row in cur.fetchall()
                        ]
                        if users:
                            conn.commit()
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

@app.post("/get_user_info", response_model=UserInfoResponse)
def get_user_info(data: GetUserInfoRequest):
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (data.requestUserName,))
        request_user_uuid = cur.fetchone()
        if request_user_uuid:
            cur.execute("SELECT token FROM logins WHERE useruuid = %s and token = %s", (request_user_uuid[0], data.requestUserToken,))
            token_info=cur.fetchone()
            if token_info:
                cur.execute("SELECT role FROM users WHERE useruuid = %s", (request_user_uuid[0],))
                request_user_role = cur.fetchone()
                if request_user_role:
                    if request_user_role[0] == "ADMIN":
                        cur.execute("SELECT username, useruuid, createdat, role, lastlogin, name, email, birthdate FROM users WHERE useruuid = %s", (data.useruuid,))
                        user_info = cur.fetchone()
                        if user_info:
                            return{"status": "success", "username": user_info[0], "useruuid": user_info[1], "createdat": user_info[2], "role": user_info[3], "lastlogin": user_info[4], "name": user_info[5], "email": user_info[6], "birthdate": user_info[7]}
                        else:
                            raise HTTPException(
                                status_code=404,
                                detail="User not found"
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