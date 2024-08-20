from sanic import Sanic, response
from sanic.response import html, redirect
from sanic_session import Session, InMemorySessionInterface
import bcrypt
import aiosqlite
import os
import datetime

app = Sanic(__name__)
session = Session(app, interface=InMemorySessionInterface())

DATABASE = "users.db"

async def setup_db():
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        await db.commit()

@app.listener('before_server_start')
async def before_server_start(app, loop):
    await setup_db()

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(stored_password, provided_password):
    if isinstance(stored_password, str):
        stored_password = stored_password.encode('utf-8')
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

@app.route('/')
async def home(request):
    if request.ctx.session.get('user'):
        return redirect('/dashboard')
    return await response.file('./templates/index.html')

@app.route('/register', methods=['GET', 'POST'])
async def register(request):
    if request.method == 'GET':
        return await response.file('./templates/register.html')
    
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not email or not password or password != confirm_password:
        return html('<h3>Registration failed: Invalid data or passwords do not match.</h3>', status=400)

    hashed_password = hash_password(password)

    async with aiosqlite.connect(DATABASE) as db:
        try:
            await db.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
            await db.commit()
        except aiosqlite.IntegrityError:
            return html('<h3>Registration failed: Email already registered.</h3>', status=400)

    request.ctx.session['user'] = email
    return redirect('/dashboard')

@app.route('/login', methods=['GET', 'POST'])
async def login(request):
    if request.method == 'GET':
        return await response.file('./templates/login.html')
    
    email = request.form.get('email')
    password = request.form.get('password')

    async with aiosqlite.connect(DATABASE) as db:
        cursor = await db.execute("SELECT password FROM users WHERE email = ?", (email,))
        row = await cursor.fetchone()

    if row and verify_password(row[0], password):
        request.ctx.session['user'] = email
        return redirect('/dashboard')
    else:
        return html('<h3>Login failed: Invalid credentials.</h3>', status=401)

@app.route('/dashboard')
async def dashboard(request):
    user = request.ctx.session.get('user')
    if not user:
        return redirect('/')
    return html(open('./templates/dashboard.html').read().replace("{user}", user))

@app.route('/logout')
async def logout(request):
    request.ctx.session.clear()
    return redirect('/')

app.static('/static', './static')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)