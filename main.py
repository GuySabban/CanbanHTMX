from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import sqlite3
import hashlib
from lib.db import DB

app = FastAPI()
templates = Jinja2Templates(directory="templates")
db = DB()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# API
@app.post("/api/login_or_register")
def login_or_register(form_data: OAuth2PasswordRequestForm = Depends()):
    user_exists = db.does_username_exist(form_data.username) 
    
    if user_exists:
        code, data = db.login(form_data.username, form_data.password)
        
        if code == 401:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=data
            )
            
        return {"token": data}
    else:
        code, data = db.register(form_data.username, form_data.password)
        
        if code == 409:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=data
            )
            
        return {"token": data}
