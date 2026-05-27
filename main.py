from fastapi import FastAPI, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import sqlite3
import hashlib
from lib.db import DB

app = FastAPI()
templates = Jinja2Templates(directory="templates")
db = DB()

app.mount("/public", StaticFiles(directory="public"), name="public")

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
@app.get("/api/user-status")
def get_user_status(request: Request):
    auth = request.headers.get("Authorization")
    
    if auth and auth.startswith('Bearer '):
        token = auth.split(" ")[1]
        
        if db.is_token_valid(token):
            return templates.TemplateResponse(request=request, name="homepage.html")
        
    return templates.TemplateResponse(request=request, name="login.html")
        
@app.post("/api/check_username", response_class=PlainTextResponse)
def check_username(username: str = Form(...)):
    user_exists = db.does_username_exist(username)
    
    if user_exists:
        return "Sign In"
    
    return "Sign Up" 
