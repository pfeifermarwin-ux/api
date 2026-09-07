from fastapi import FastAPI
from pydantic import BaseModel
import psycopg
from passlib.context import CryptContext

app = FastAPI(
    root_path="/api"
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

conn = psycopg.connect(
    host="100.125.8.79",
    port=5432,
    dbname="platform-db",
    user="db_user",
    password="20mp10gc-DB"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

@app.get("/")
def home():
    return {"message": "online"}

class user(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: user):
    username = user.username
    password = user.password
    passwordHash = hash_password(password)
    with conn.cursor() as cur:
        cur.execute("INSERT INTO users (username, passwordhash) VALUES (%s, %s)", (username, passwordHash))
        conn.commit()
    return {"status": "success", "message": "User registered successfully."}
