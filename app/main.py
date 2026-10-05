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

class BlockUserRequest(BaseModel):
    useruuidToBlock: UUID
    token: UUID
    username: str

class UnblockUserRequest(BaseModel):
    useruuidToUnblock: UUID
    token: UUID
    username: str

class GetUserLogsRequest(BaseModel):
    useruuidforlog: UUID
    token: UUID
    username: str

class GetLogByLoguuidRequest(BaseModel):
    loguuid: UUID
    token: UUID
    username: str

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
                    cur.execute("SELECT isblocked FROM users WHERE useruuid = %s", (uuid[0],))
                    blockstatus = cur.fetchone()
                    if blockstatus:    
                        if blockstatus[0] == False:
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
                            log(uuid[0], "WARNING", "User is blocked", "/login", 403, user.model_dump(exclude={"password"}))
                            raise HTTPException(
                                status_code=403,
                                detail="User is Blocked"
                            )
                    else:
                        log(uuid[0], "ERROR", "no blockstatus", "/login", 401, user.model_dump(exclude={"password"}))
                        raise HTTPException(
                            status_code=500,
                            detail="no blockstatus"
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
            log(None, "INFO", "Logged out successfully", "/logout", 200, data.model_dump())
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
        log(None, "WARNING", "Request without Token", "/check_token", 401, data.model_dump())
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
                log(None, "INFO", "Token is valid", "/check_token", 200, data.model_dump())
                return {"status": "success", "message": "Token is valid."}
            else:
                log(None, "WARNING", "Invalid token", "/check_token", 401, data.model_dump())
                raise HTTPException(
                    status_code=401,
                    detail="Invalid token"
                )
        else:
            log(None, "WARNING", "User not found", "/check_token", 404, data.model_dump())
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
                            log(user_uuid[0], "INFO", "Get users success", "/get_users", 200, data.model_dump())
                            return{"status": "success", "users": users}
                        else:
                            log(user_uuid[0], "ERROR", "Users not found", "/get_users", 500, data.model_dump())
                            raise HTTPException(
                                status_code=500,
                                detail="Users not found"
                            )
                    else:
                        log(user_uuid[0], "WARNING", "Access denied; required permission is missing", "/get_users", 403, data.model_dump())
                        raise HTTPException(
                            status_code=403,
                            detail="Access denied; required permission is missing."
                        )
                else:
                    log(user_uuid[0], "WARNING", "User role is missing", "/get_users", 500, data.model_dump())
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
            else:
                log(user_uuid[0], "WARNING", "Token is invalid or expired", "/get_users", 401, data.model_dump())
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            log(None, "WARNING", "User not found", "/get_users", 404, data.model_dump())
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
                    log(user_uuid[0], "INFO", "Get role success", "/get_role", 200, data.model_dump())
                    return{"status": "success", "role": role[0]}
                else:
                    log(user_uuid[0], "WARNING", "User role is missing", "/get_role", 500, data.model_dump())
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
            else:
                log(user_uuid[0], "WARNING", "Token is invalid or expired", "/get_role", 401, data.model_dump())
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            log(None, "WARNING", "User not found", "/get_role", 404, data.model_dump())
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
                        cur.execute("SELECT username, useruuid, createdat, role, lastlogin, name, email, birthdate, isblocked FROM users WHERE useruuid = %s", (data.useruuid,))
                        user_info = cur.fetchone()
                        if user_info:
                            log(request_user_uuid[0], "INFO", "Get user_info request", "/get_user_info", 200, data.model_dump())
                            return{"status": "success", "username": user_info[0], "useruuid": user_info[1], "createdat": user_info[2], "role": user_info[3], "lastlogin": user_info[4], "name": user_info[5], "email": user_info[6], "birthdate": user_info[7], "isblocked": user_info[8]}
                        else:
                            log(request_user_uuid[0], "WARNING", "User not found", "/get_user_info", 404, data.model_dump())
                            raise HTTPException(
                                status_code=404,
                                detail="User not found"
                            )
                    else:
                        log(request_user_uuid[0], "WARNING", "Access denied; required permission is missing", "/get_user_info", 403, data.model_dump())
                        raise HTTPException(
                                status_code=403,
                                detail="Access denied; required permission is missing."
                        )
                else:
                   log(request_user_uuid[0], "ERROR", "User role is missing", "/get_user_info", 500, data.model_dump())
                   raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    ) 
            else:
                log(request_user_uuid[0], "WARNING", "Token is invalid or expired", "/get_user_info", 401, data.model_dump())
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            log(None, "WARNING", "User not found", "/get_user_info", 404, data.model_dump())
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

@app.post("/block_user")
def block_user(data: BlockUserRequest):
    usertoblock = data.useruuidToBlock
    token = data.token
    username = data.username
    if not token:
        log(None, "WARNING", "Request without token", "/block_user", 401, data.model_dump())
        raise HTTPException(
            status_code=401,
            detail="Token is required"
        )
    if not username:
            log(None, "WARNING", "Request without username", "/block_user", 401, data.model_dump())
            raise HTTPException(
                status_code=401,
                detail="Username is required"
            )
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (username,))
        useruuid = cur.fetchone()
        if useruuid:
            cur.execute("SELECT token FROM logins WHERE token = %s AND useruuid = %s", (token,useruuid[0],))
            tokenInfo = cur.fetchone()
            if tokenInfo:
                cur.execute("SELECT role FROM users WHERE useruuid = %s", (useruuid[0],))
                role = cur.fetchone()
                if role:
                    if role[0] == 'ADMIN':
                        cur.execute("UPDATE users SET isblocked = true WHERE useruuid = %s",(usertoblock,))
                        conn.commit()
                        log(useruuid[0], "INFO", "Block user success", "/block_user", 200, data.model_dump(mode="json"))
                        return{"status": "success", "message": "user successfully blocked"}
                    else:
                        log(useruuid[0], "WARNING", "Access denied; required permission is missing", "/block_user", 403, data.model_dump(mode="json"))
                        raise HTTPException(
                                status_code=403,
                                detail="Access denied; required permission is missing."
                        )
                else:
                    log(useruuid[0], "ERROR", "User role is missing", "/block_user", 500, data.model_dump(mode="json"))
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
            else:
                log(useruuid[0], "WARNING", "Token is invalid or expired", "/block_user", 401, data.model_dump(mode="json"))
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            log(None, "WARNING", "User not found", "/block_user", 404, data.model_dump(mode="json"))
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

@app.post("/unblock_user")
def unblock_user(data: UnblockUserRequest):
    usertounblock = data.useruuidToUnblock
    token = data.token
    username = data.username
    if not token:
        log(None, "WARNING", "Request without token", "/unblock_user", 401, data.model_dump())
        raise HTTPException(
            status_code=401,
            detail="Token is required"
        )
    if not username:
            log(None, "WARNING", "Request without username", "/unblock_user", 401, data.model_dump())
            raise HTTPException(
                status_code=401,
                detail="Username is required"
            )
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (username,))
        useruuid = cur.fetchone()
        if useruuid:
            cur.execute("SELECT token FROM logins WHERE token = %s AND useruuid = %s", (token,useruuid[0],))
            tokenInfo = cur.fetchone()
            if tokenInfo:
                cur.execute("SELECT role FROM users WHERE useruuid = %s", (useruuid[0],))
                role = cur.fetchone()
                if role:
                    if role[0] == 'ADMIN':
                        cur.execute("UPDATE users SET isblocked = false WHERE useruuid = %s",(usertounblock,))
                        conn.commit()
                        log(useruuid[0], "INFO", "Unblock user success", "/unblock_user", 200, data.model_dump(mode="json"))
                        return{"status": "success", "message": "user successfully Unblocked"}
                    else:
                        log(useruuid[0], "WARNING", "Access denied; required permission is missing", "/block_user", 403, data.model_dump(mode="json"))
                        raise HTTPException(
                                status_code=403,
                                detail="Access denied; required permission is missing."
                        )
                else:
                    log(useruuid[0], "ERROR", "User role is missing", "/unblock_user", 500, data.model_dump(mode="json"))
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
            else:
                log(useruuid[0], "WARNING", "Token is invalid or expired", "/unblock_user", 401, data.model_dump(mode="json"))
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            log(None, "WARNING", "User not found", "/unblock_user", 404, data.model_dump(mode="json"))
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

@app.post("/getUserLogs")#
def getUserLogs(data: GetUserLogsRequest):
    useruuidforlog = data.useruuidforlog
    token = data.token
    username = data.username
    if not token:
            log(None, "WARNING", "Request without token", "/getUserLogs", 401, data.model_dump())
            raise HTTPException(
                status_code=401,
                detail="Token is required"
            )
    if not username:
            log(None, "WARNING", "Request without username", "/getUserLogs", 401, data.model_dump())
            raise HTTPException(
                status_code=401,
                detail="Username is required"
            )
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (username,))
        useruuid = cur.fetchone()
        if useruuid:
            cur.execute("SELECT token FROM logins WHERE token = %s AND useruuid = %s", (token,useruuid[0],))
            tokenInfo = cur.fetchone()
            if tokenInfo:
                cur.execute("SELECT role FROM users WHERE useruuid = %s", (useruuid[0],))
                role = cur.fetchone()
                if role:
                    if role[0] == 'ADMIN':
                        cur.execute("SELECT * FROM logs WHERE useruuid = %s", (useruuidforlog,))
                        logs = [
                            {
                                "loguuid": row[1],
                                "level": row[2],
                                "message": row[3],
                                "created_at": row[4],
                                "path": row[5],
                                "status_code": row[6],
                                "metadata": row[7]
                            }
                            for row in cur.fetchall()
                        ]
                        if logs:
                            conn.commit()
                            log(useruuid[0], "INFO", "Get Log success", "/getUserLogs", 200, data.model_dump(mode="json"))
                            return{"status": "success", "logs": logs}
                        else:
                            pass
                    else:
                        log(useruuid[0], "WARNING", "Access denied; required permission is missing", "/getUserLogs", 403, data.model_dump(mode="json"))
                        raise HTTPException(
                                status_code=403,
                                detail="Access denied; required permission is missing."
                        )
                else:
                    log(useruuid[0], "ERROR", "User role is missing", "/getUserLogs", 500, data.model_dump(mode="json"))
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
            else:
                log(useruuid[0], "WARNING", "Token is invalid or expired", "/getUserLogs", 401, data.model_dump(mode="json"))
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                ) 
        else:
            log(None, "WARNING", "User not found", "/getUserLogs", 404, data.model_dump(mode="json"))
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

@app.post("/get_log_by_loguuid")
def get_log_by_loguuid(data: GetLogByLoguuidRequest):
    loguuid = data.loguuid
    username = data.username
    token = data.token
    if not token:
            log(None, "WARNING", "Request without token", "/get_log_by_loguuid", 401, data.model_dump())
            raise HTTPException(
                status_code=401,
                detail="Token is required"
            )
    if not username:
            log(None, "WARNING", "Request without username", "/get_log_by_loguuid", 401, data.model_dump())
            raise HTTPException(
                status_code=401,
                detail="Username is required"
            )
    with conn.cursor() as cur:
        cur.execute("SELECT useruuid FROM users WHERE username = %s", (username,))
        useruuid = cur.fetchone()
        if useruuid:
            cur.execute("SELECT token FROM logins WHERE token = %s AND useruuid = %s", (token,useruuid[0],))
            tokenInfo = cur.fetchone()
            if tokenInfo:
                cur.execute("SELECT role FROM users WHERE useruuid = %s", (useruuid[0],))
                role = cur.fetchone()
                if role:
                    if role[0] == 'ADMIN':
                        cur.execute("SELECT * FROM logs WHERE loguuid = %s", (loguuid,))
                        log_entry = cur.fetchone()
                        if log_entry:
                            log(useruuid[0], "INFO", "Get Log by loguuid success", "/get_log_by_loguuid", 200, data.model_dump(mode="json"))
                            return {
                                "status": "success",
                                "log": {
                                    "loguuid": log_entry[1],
                                    "level": log_entry[2],
                                    "message": log_entry[3],
                                    "created_at": log_entry[4],
                                    "path": log_entry[5],
                                    "status_code": log_entry[6],
                                    "metadata": log_entry[7]
                                }
                            }
                        else:
                            log(useruuid[0], "WARNING", "Log entry not found", "/get_log_by_loguuid", 404, data.model_dump())
                            raise HTTPException(
                                status_code=404,
                                detail="Log entry not found"
                            )
                    else:
                        log(useruuid[0], "WARNING", "Access denied; required permission is missing", "/get_log_by_loguuid", 403, data.model_dump())
                        raise HTTPException(
                                status_code=403,
                                detail="Access denied; required permission is missing."
                        )
                else:
                    log(useruuid[0], "ERROR", "User role is missing", "/get_log_by_loguuid", 500, data.model_dump())
                    raise HTTPException(
                        status_code=500,
                        detail="User role is missing"
                    )
                    
            else:
                log(useruuid[0], "WARNING", "Token is invalid or expired", "/get_log_by_loguuid", 401, data.model_dump())
                raise HTTPException(
                    status_code=401,
                    detail="Token is invalid or expired"
                )
        else:
            log(None, "WARNING", "User not found", "/get_log_by_loguuid", 404, data.model_dump())
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )