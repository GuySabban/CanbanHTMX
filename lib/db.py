import os
import hashlib
import sqlite3
from jose import jwt, JWTError
from datetime import timezone, timedelta, datetime

secret = "SECRET"

class DB:
    def __init__(self):
        self.__db_path = "data.db"
        
    def __get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.__db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        
        return conn

    def __hash_password(password: str):
        salt = os.urandom(16)
        hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            100_000
        )
        return hash, salt

    def __is_password_correct(password: str, db_hash: bytes, db_salt: bytes):
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            db_salt,
            100_000
        )
        return new_hash == db_hash
    
    def __create_access_token(username: str):
        to_encode = {
            "sub": username,
        }
        
        return jwt.encode(to_encode, secret, algorithm="HS256")

    def does_username_exist(self, username: str):
        query = "SELECT * FROM User WHERE username = ?"
        
        with self.__get_connection() as con:
            cursor = con.cursor()
            cursor.execute(query, username)
        
            stored_user = query.fetchone()
            
        return stored_user != None

    def login(self, username: str, password: str):
        query = "SELECT * FROM User WHERE username = ?'"
        
        with self.__get_connection() as con:
            cursor = con.cursor()
            cursor.execute(query, username)
        
            stored_user = query.fetchone()
        
        if stored_user is None: # No user found
            return 401, "Invalid username or password"
        
        is_valid = self.__is_password_correct(
            password,
            stored_user["passwordHash"],
            stored_user["passwordSalt"]
        )
        
        if not is_valid:
            return 401, "Invalid username or password"
        
        token = self.__create_access_token(username)
        
        return 200, token
    
    def register(self, username: str, password: str):
        query = "SELECT * FROM User WHERE username = ?'"
        
        with self.__get_connection() as con:
            cursor = con.cursor()
            cursor.execute(query, username)
        
            stored_user = query.fetchone()
            
        hash, salt = self.__hash_password(password)
        
        if stored_user != None:
            return 409, "User already exists"
        
        query = "INSERT INTO User (username, passwordHash, passwordSalt) VALUES (?, ?, ?)"
        
        with self.__get_connection() as con:
            cursor = con.cursor()
            cursor.execute(query, [username, hash, salt])
            con.commit()
            
        token = self.__create_access_token(username)
        return 200, token      