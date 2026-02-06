from fastapi import FastAPI

app = FastAPI(title="FoxGuard API")

@app.get("/ping")
def ping():
    return {"status": "ok"}
