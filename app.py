from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token():
    token = request.form.get('csrf_token')
    return token and token == session.get('csrf_token')

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf_token()}

def get_db_connection():
    conn = sqlite3.connect('tournament.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            creator_id INTEGER,
            FOREIGN KEY (creator_id) REFERENCES users (id)
        )
    ''')
    
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


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    tournaments = conn.execute('SELECT * FROM tournaments ORDER BY id DESC LIMIT 5').fetchall()
    teams = conn.execute('SELECT * FROM teams ORDER BY id DESC LIMIT 5').fetchall()
    conn.close()
    
    return render_template('index.html', tournaments=tournaments, teams=teams)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Неверный запрос')
            return render_template('register.html', csrf_token=generate_csrf_token())
            
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Все поля обязательны для заполнения')
            return render_template('register.html', csrf_token=generate_csrf_token())
        
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('Пользователь с таким именем уже существует')
            conn.close()
            return render_template('register.html', csrf_token=generate_csrf_token())
        
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Регистрация прошла успешно! Теперь вы можете войти в систему.')
        return redirect(url_for('login'))
    
    return render_template('register.html', csrf_token=generate_csrf_token())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Неверный запрос')
            return render_template('login.html', csrf_token=generate_csrf_token())
            
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Введите имя пользователя и пароль')
            return render_template('login.html', csrf_token=generate_csrf_token())
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль')
    
    return render_template('login.html', csrf_token=generate_csrf_token())

@app.route('/logout', methods=['POST'])
def logout():
    if not validate_csrf_token():
        flash('Неверный запрос')
        return redirect(url_for('index'))
    session.clear()
    return redirect(url_for('login'))

@app.route('/teams')
def teams():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
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
    
    return render_template('teams.html', teams=teams, csrf_token=generate_csrf_token())

@app.route('/create_team', methods=['GET', 'POST'])
def create_team():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Неверный запрос')
            return render_template('create_team.html', csrf_token=generate_csrf_token())
            
        name = request.form['name']
        description = request.form['description']
        
        if not name:
            flash('Название команды обязательно')
            return render_template('create_team.html', csrf_token=generate_csrf_token())
        
        conn = get_db_connection()
        cursor = conn.execute('INSERT INTO teams (name, description, creator_id) VALUES (?, ?, ?)', 
                    (name, description, session['user_id']))
        team_id = cursor.lastrowid
        conn.execute('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)', 
                    (team_id, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Команда успешно создана!')
        return redirect(url_for('teams'))
    
    return render_template('create_team.html', csrf_token=generate_csrf_token())

@app.route('/tournaments')
def tournaments():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
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
    
    return render_template('tournaments.html', tournaments=tournaments)

@app.route('/create_tournament', methods=['GET', 'POST'])
def create_tournament():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Неверный запрос')
            return render_template('create_tournament.html', csrf_token=generate_csrf_token())
            
        name = request.form['name']
        description = request.form['description']
        max_teams = request.form.get('max_teams', 16)
        
        if not name:
            flash('Название турнира обязательно')
            return render_template('create_tournament.html', csrf_token=generate_csrf_token())
        
        conn = get_db_connection()
        conn.execute('INSERT INTO tournaments (name, description, max_teams, creator_id) VALUES (?, ?, ?, ?)', 
                    (name, description, max_teams, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Турнир успешно создан!')
        return redirect(url_for('tournaments'))
    
    return render_template('create_tournament.html', csrf_token=generate_csrf_token())

@app.route('/join_team/<int:team_id>', methods=['POST'])
def join_team(team_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if not validate_csrf_token():
        flash('Неверный запрос')
        return redirect(url_for('teams'))
    
    conn = get_db_connection()
    existing_member = conn.execute('SELECT id FROM team_members WHERE team_id = ? AND user_id = ?', 
                                  (team_id, session['user_id'])).fetchone()
    
    if existing_member:
        flash('Вы уже являетесь участником этой команды')
    else:
        conn.execute('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)', 
                    (team_id, session['user_id']))
        conn.commit()
        flash('Вы успешно присоединились к команде!')
    
    conn.close()
    return redirect(url_for('teams'))

@app.route('/join_tournament', methods=['POST'])
def join_tournament():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if not validate_csrf_token():
        flash('Неверный запрос')
        return redirect(url_for('my_teams'))
        
    tournament_id = request.form.get('tournament_id', type=int)
    team_id = request.form.get('team_id', type=int)
    
    if not tournament_id or not team_id:
        flash('Неверные параметры')
        return redirect(url_for('my_teams'))
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    is_team_member = conn.execute('SELECT id FROM team_members WHERE team_id = ? AND user_id = ?', 
                                 (team_id, session['user_id'])).fetchone()
    
    if not is_team_member:
        flash('Вы не являетесь участником этой команды')
        conn.close()
        return redirect(url_for('tournaments'))
    
    existing_entry = conn.execute('SELECT id FROM tournament_teams WHERE tournament_id = ? AND team_id = ?', 
                                 (tournament_id, team_id)).fetchone()
    
    if existing_entry:
        flash('Команда уже зарегистрирована в этом турнире')
    else:
        tournament = conn.execute('SELECT max_teams FROM tournaments WHERE id = ?', (tournament_id,)).fetchone()
        current_teams = conn.execute('SELECT COUNT(*) as count FROM tournament_teams WHERE tournament_id = ?', 
                                   (tournament_id,)).fetchone()
        
        if current_teams['count'] >= tournament['max_teams']:
            flash('Турнир уже заполнен')
        else:
            conn.execute('INSERT INTO tournament_teams (tournament_id, team_id) VALUES (?, ?)', 
                        (tournament_id, team_id))
            conn.commit()
            flash('Команда успешно зарегистрирована в турнире!')
    
    conn.close()
    return redirect(url_for('tournaments'))

@app.route('/my_teams')
def my_teams():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    my_teams = conn.execute('''
        SELECT t.* FROM teams t
        JOIN team_members tm ON t.id = tm.team_id
        WHERE tm.user_id = ?
        ORDER BY t.id DESC
    ''', (session['user_id'],)).fetchall()
    
    tournaments = conn.execute('SELECT * FROM tournaments ORDER BY id DESC').fetchall()
    conn.close()
    
    return render_template('my_teams.html', teams=my_teams, tournaments=tournaments, csrf_token=generate_csrf_token())

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)