from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

import sqlite3
import os
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for login sessions

# --- DB Initialization ---
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[0-9]", password):  # at least one digit
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # at least one special char
        return False
    return True

def init_db():
    if not os.path.exists('database.db'):
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT NOT NULL,
                due_date TEXT,
                priority TEXT,
                completed INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
        conn.close()

init_db()  # CALL THE FUNCTION HERE (only once)

# --- ROUTES ---

@app.route('/')
def home():
    username = session['username'] if 'username' in session else None
    return render_template('home.html', username=username)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_strong_password(password):
            error = "Password must be at least 8 characters long and include at least one number and one special character."
            return render_template('register.html', error=error)

        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            conn.close()
            flash('Account created successfully! Please log in.')
            return redirect('/login')
        except:
            flash('Username already taken. Try again.', 'error')
            return render_template('register.html')

    # ✅ This was missing:
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash(f"Welcome back, {username}!")
            return redirect('/')
        else:
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

    # ✅ always return this in case method == 'GET'
    return render_template('login.html')



@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        task = request.form['task']
        due_date = request.form['due_date']
        priority = request.form['priority']

        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("INSERT INTO tasks (user_id, content, due_date, priority) VALUES (?, ?, ?, ?)",
                      (session['user_id'], task, due_date, priority))

            flash('Task added successfully!')
            conn.commit()

    filter_by = request.args.get('filter', 'all')  # get filter from URL

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()

        if filter_by == 'completed':
            c.execute(
                "SELECT id, content, due_date, priority, completed FROM tasks WHERE user_id = ? AND completed = 1",
                (session['user_id'],))
        elif filter_by == 'incomplete':
            c.execute(
                "SELECT id, content, due_date, priority, completed FROM tasks WHERE user_id = ? AND completed = 0",
                (session['user_id'],))
        else:
            c.execute("SELECT id, content, due_date, priority, completed FROM tasks WHERE user_id = ?",
                      (session['user_id'],))

        user_tasks = c.fetchall()

    return render_template('tasks.html', tasks=user_tasks)


@app.route('/complete/<int:task_id>')
def complete_task(task_id):
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE tasks SET completed = 1 WHERE id = ? AND user_id = ?", (task_id, session['user_id']))
        conn.commit()
        conn.close()
    return redirect('/tasks')

@app.route('/delete/<int:task_id>')
def delete_task(task_id):
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, session['user_id']))
        conn.commit()
        conn.close()
    return redirect('/tasks')

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if request.method == 'POST':
        new_content = request.form['content']
        new_due_date = request.form['due_date']
        new_priority = request.form['priority']
        c.execute("UPDATE tasks SET content = ?, due_date = ?, priority = ? WHERE id = ? AND user_id = ?",
                  (new_content, new_due_date, new_priority, task_id, session['user_id']))
        conn.commit()
        conn.close()
        return redirect('/tasks')

    c.execute("SELECT id, content, due_date, priority, completed FROM tasks WHERE id = ? AND user_id = ?",
              (task_id, session['user_id']))
    task = c.fetchone()
    conn.close()
    return render_template('edit_task.html', task=task)

@app.route('/incomplete/<int:task_id>')
def mark_incomplete(task_id):
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE tasks SET completed = 0 WHERE id = ? AND user_id = ?", (task_id, session['user_id']))
        conn.commit()
        conn.close()
    return redirect('/tasks')


if __name__ == '__main__':
    app.run(debug=True)
