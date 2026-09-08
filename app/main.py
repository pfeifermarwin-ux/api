from fastapi import FastAPI
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

@app.post("/register")
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
        return {
            "status": "error",
            "message": "Username already exists."
        }
    return {"status": "success", "message": "User registered successfully."}

@app.post("/login")
def login(user: User):
    username = user.username
    password = user.password
    try:
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
                            return {"status": "error", "message": "Failed to create login session."}
                    else:
                        return {"status": "error", "message": "Incorrect password."}
            else:
                return {"status": "error", "message": "User not found."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/logout")
def logout(token: str):
    if not token:
        return {"status": "error", "message": "Token is required."}
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM logins WHERE token = %s", (token,))
            deleted_rows = cur.rowcount
            conn.commit()
            if deleted_rows > 0:
                return {"status": "success", "message": "Logged out successfully."}
            else:
                return {"status": "error", "message": "Invalid token."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/check_token")
def check_token(token: str, user: User):
    if not token:
        return {"status": "error", "message": "Token is required."}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT useruuid FROM users WHERE username = %s", (user.username,))
            user_uuid = cur.fetchone()
            if user_uuid:
                cur.execute("SELECT passwordhash FROM users WHERE useruuid = %s", (user_uuid[0],))
                stored_password_hash = cur.fetchone()
                if stored_password_hash:
                    if verify_password(user.password, stored_password_hash[0]):
                        cur.execute("SELECT token FROM logins WHERE useruuid = %s AND token = %s", (user_uuid[0], token))
                        token_info = cur.fetchone()
                        if token_info:
                            return {"status": "success", "message": "Token is valid."}
                        else:
                            return {"status": "error", "message": "Invalid token."}
                    else:
                        return {"status": "error", "message": "Incorrect password."}
                else:
                    return {"status": "error", "message": "User not found."}
            else:
                return {"status": "error", "message": "User not found."}
    except Exception as e:
        return {"status": "error", "message": str(e)}