from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets
from typing import Optional

# Создаем приложение FastAPI
app = FastAPI(title="Tournament Management System")

# Настройка сессий
app.add_middleware(SessionMiddleware, secret_key=os.environ.get('SECRET_KEY', secrets.token_hex(32)))

# Настройка шаблонов
templates = Jinja2Templates(directory="templates")

def generate_csrf_token(request: Request) -> str:
    """Генерирует CSRF токен для защиты форм"""
    if 'csrf_token' not in request.session:
        request.session['csrf_token'] = secrets.token_hex(16)
    return request.session['csrf_token']

def validate_csrf_token(request: Request, csrf_token: str = Form(...)) -> bool:
    """Проверяет CSRF токен"""
    session_token = request.session.get('csrf_token')
    return bool(csrf_token and csrf_token == session_token)

def get_db_connection():
    """Подключение к базе данных"""
    conn = sqlite3.connect('tournament.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Инициализация базы данных"""
    conn = get_db_connection()
    
    # Создание таблицы пользователей
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Создание таблицы команд
    conn.execute('''
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            creator_id INTEGER,
            FOREIGN KEY (creator_id) REFERENCES users (id)
        )
    ''')
    
    # Создание таблицы турниров
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tournaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            creator_id INTEGER,
            max_teams INTEGER DEFAULT 16,
            FOREIGN KEY (creator_id) REFERENCES users (id)
        )
    ''')
    
    # Создание таблицы участников команд
    conn.execute('''
        CREATE TABLE IF NOT EXISTS team_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            user_id INTEGER,
            FOREIGN KEY (team_id) REFERENCES teams (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(team_id, user_id)
        )
    ''')
    
    # Создание таблицы команд в турнирах
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tournament_teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tournament_id INTEGER,
            team_id INTEGER,
            FOREIGN KEY (tournament_id) REFERENCES tournaments (id),
            FOREIGN KEY (team_id) REFERENCES teams (id),
            UNIQUE(tournament_id, team_id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_current_user(request: Request):
    """Получение текущего пользователя из сессии"""
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    return {"id": user_id, "username": request.session.get('username')}

def require_auth(request: Request):
    """Проверка аутентификации пользователя"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    return user

# Маршруты приложения

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Главная страница"""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    conn = get_db_connection()
    tournaments = conn.execute('SELECT * FROM tournaments ORDER BY id DESC LIMIT 5').fetchall()
    teams = conn.execute('SELECT * FROM teams ORDER BY id DESC LIMIT 5').fetchall()
    conn.close()
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "tournaments": tournaments,
        "teams": teams,
        "csrf_token": generate_csrf_token(request),
        "username": user['username'],
        "user_id": user['id']
    })

@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    """Форма регистрации"""
    return templates.TemplateResponse("register.html", {
        "request": request,
        "csrf_token": generate_csrf_token(request)
    })

@app.post("/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...)
):
    """Обработка регистрации"""
    # Проверка CSRF токена
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Неверный запрос",
            "csrf_token": generate_csrf_token(request)
        })
    
    # Проверка данных
    if not username or not password:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Все поля обязательны для заполнения",
            "csrf_token": generate_csrf_token(request)
        })
    
    conn = get_db_connection()
    existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    
    if existing_user:
        conn.close()
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь с таким именем уже существует",
            "csrf_token": generate_csrf_token(request)
        })
    
    # Создание пользователя
    hashed_password = generate_password_hash(password)
    conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "success": "Регистрация прошла успешно! Теперь вы можете войти в систему.",
        "csrf_token": generate_csrf_token(request)
    })

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """Форма входа"""
    return templates.TemplateResponse("login.html", {
        "request": request,
        "csrf_token": generate_csrf_token(request)
    })

@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...)
):
    """Обработка входа"""
    # Проверка CSRF токена
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверный запрос",
            "csrf_token": generate_csrf_token(request)
        })
    
    # Проверка данных
    if not username or not password:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Введите имя пользователя и пароль",
            "csrf_token": generate_csrf_token(request)
        })
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        request.session['user_id'] = user['id']
        request.session['username'] = user['username']
        return RedirectResponse(url="/", status_code=302)
    else:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверное имя пользователя или пароль",
            "csrf_token": generate_csrf_token(request)
        })

@app.post("/logout")
async def logout(request: Request, csrf_token: str = Form(...)):
    """Выход из системы"""
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/", status_code=302)
    
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

@app.get("/teams", response_class=HTMLResponse)
async def teams_list(request: Request):
    """Список команд"""
    user = require_auth(request)
    
    conn = get_db_connection()
    teams = conn.execute('''
        SELECT t.*, u.username as creator_name, 
               COUNT(tm.user_id) as member_count
        FROM teams t 
        LEFT JOIN users u ON t.creator_id = u.id
        LEFT JOIN team_members tm ON t.id = tm.team_id
        GROUP BY t.id
        ORDER BY t.id DESC
    ''').fetchall()
    conn.close()
    
    return templates.TemplateResponse("teams.html", {
        "request": request,
        "teams": teams,
        "csrf_token": generate_csrf_token(request),
        "username": user['username'],
        "user_id": user['id']
    })

@app.get("/create_team", response_class=HTMLResponse)
async def create_team_form(request: Request):
    """Форма создания команды"""
    user = require_auth(request)
    
    return templates.TemplateResponse("create_team.html", {
        "request": request,
        "csrf_token": generate_csrf_token(request),
        "username": user['username'],
        "user_id": user['id']
    })

@app.post("/create_team")
async def create_team_submit(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    csrf_token: str = Form(...)
):
    """Создание команды"""
    user = require_auth(request)
    
    # Проверка CSRF токена
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse("create_team.html", {
            "request": request,
            "error": "Неверный запрос",
            "csrf_token": generate_csrf_token(request)
        })
    
    if not name:
        return templates.TemplateResponse("create_team.html", {
            "request": request,
            "error": "Название команды обязательно",
            "csrf_token": generate_csrf_token(request)
        })
    
    conn = get_db_connection()
    cursor = conn.execute('INSERT INTO teams (name, description, creator_id) VALUES (?, ?, ?)', 
                         (name, description, user['id']))
    team_id = cursor.lastrowid
    conn.execute('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)', 
                (team_id, user['id']))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/teams", status_code=302)

@app.get("/tournaments", response_class=HTMLResponse)
async def tournaments_list(request: Request):
    """Список турниров"""
    user = require_auth(request)
    
    conn = get_db_connection()
    tournaments = conn.execute('''
        SELECT t.*, u.username as creator_name, 
               COUNT(tt.team_id) as team_count
        FROM tournaments t 
        LEFT JOIN users u ON t.creator_id = u.id
        LEFT JOIN tournament_teams tt ON t.id = tt.tournament_id
        GROUP BY t.id
        ORDER BY t.id DESC
    ''').fetchall()
    conn.close()
    
    return templates.TemplateResponse("tournaments.html", {
        "request": request,
        "tournaments": tournaments,
        "csrf_token": generate_csrf_token(request),
        "username": user['username'],
        "user_id": user['id']
    })

@app.get("/create_tournament", response_class=HTMLResponse)
async def create_tournament_form(request: Request):
    """Форма создания турнира"""
    user = require_auth(request)
    
    return templates.TemplateResponse("create_tournament.html", {
        "request": request,
        "csrf_token": generate_csrf_token(request),
        "username": user['username'],
        "user_id": user['id']
    })

@app.post("/create_tournament")
async def create_tournament_submit(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    max_teams: int = Form(16),
    csrf_token: str = Form(...)
):
    """Создание турнира"""
    user = require_auth(request)
    
    # Проверка CSRF токена
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse("create_tournament.html", {
            "request": request,
            "error": "Неверный запрос",
            "csrf_token": generate_csrf_token(request)
        })
    
    if not name:
        return templates.TemplateResponse("create_tournament.html", {
            "request": request,
            "error": "Название турнира обязательно",
            "csrf_token": generate_csrf_token(request)
        })
    
    conn = get_db_connection()
    conn.execute('INSERT INTO tournaments (name, description, max_teams, creator_id) VALUES (?, ?, ?, ?)', 
                (name, description, max_teams, user['id']))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/tournaments", status_code=302)

@app.post("/join_team/{team_id}")
async def join_team(
    request: Request,
    team_id: int,
    csrf_token: str = Form(...)
):
    """Присоединение к команде"""
    user = require_auth(request)
    
    # Проверка CSRF токена
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/teams", status_code=302)
    
    conn = get_db_connection()
    existing_member = conn.execute('SELECT id FROM team_members WHERE team_id = ? AND user_id = ?', 
                                  (team_id, user['id'])).fetchone()
    
    if not existing_member:
        conn.execute('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)', 
                    (team_id, user['id']))
        conn.commit()
    
    conn.close()
    return RedirectResponse(url="/teams", status_code=302)

@app.post("/join_tournament")
async def join_tournament(
    request: Request,
    tournament_id: int = Form(...),
    team_id: int = Form(...),
    csrf_token: str = Form(...)
):
    """Регистрация команды в турнире"""
    user = require_auth(request)
    
    # Проверка CSRF токена
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/my_teams", status_code=302)
    
    conn = get_db_connection()
    
    # Проверяем, является ли пользователь участником команды
    is_team_member = conn.execute('SELECT id FROM team_members WHERE team_id = ? AND user_id = ?', 
                                 (team_id, user['id'])).fetchone()
    
    if not is_team_member:
        conn.close()
        return RedirectResponse(url="/tournaments", status_code=302)
    
    # Проверяем, не зарегистрирована ли уже команда
    existing_entry = conn.execute('SELECT id FROM tournament_teams WHERE tournament_id = ? AND team_id = ?', 
                                 (tournament_id, team_id)).fetchone()
    
    if not existing_entry:
        # Проверяем лимит команд в турнире
        tournament = conn.execute('SELECT max_teams FROM tournaments WHERE id = ?', (tournament_id,)).fetchone()
        current_teams = conn.execute('SELECT COUNT(*) as count FROM tournament_teams WHERE tournament_id = ?', 
                                   (tournament_id,)).fetchone()
        
        if current_teams['count'] < tournament['max_teams']:
            conn.execute('INSERT INTO tournament_teams (tournament_id, team_id) VALUES (?, ?)', 
                        (tournament_id, team_id))
            conn.commit()
    
    conn.close()
    return RedirectResponse(url="/tournaments", status_code=302)

@app.get("/my_teams", response_class=HTMLResponse)
async def my_teams(request: Request):
    """Мои команды"""
    user = require_auth(request)
    
    conn = get_db_connection()
    my_teams = conn.execute('''
        SELECT t.* FROM teams t
        JOIN team_members tm ON t.id = tm.team_id
        WHERE tm.user_id = ?
        ORDER BY t.id DESC
    ''', (user['id'],)).fetchall()
    
    tournaments = conn.execute('SELECT * FROM tournaments ORDER BY id DESC').fetchall()
    conn.close()
    
    return templates.TemplateResponse("my_teams.html", {
        "request": request,
        "teams": my_teams,
        "tournaments": tournaments,
        "csrf_token": generate_csrf_token(request),
        "username": user['username'],
        "user_id": user['id']
    })

# Инициализация при запуске
@app.on_event("startup")
async def startup_event():
    init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", port=5000, reload=True)