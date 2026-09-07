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
