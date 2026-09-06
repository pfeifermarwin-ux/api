from fastapi import FastAPI

app = FastAPI(
    root_path="/api"
)

@app.get("/")
def home():
    return {"message": "online"}