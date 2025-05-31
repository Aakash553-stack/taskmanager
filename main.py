from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Connect to your MySQL DB
db = pymysql.connect(
    host="mmunawar.mysql.pythonanywhere-services.com",
    user="mmunawar",
    password="zxcvbn@1",
    database="mmunawar$default"
)

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

@app.route('/')
def home():
    username = session.get('username')
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
        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
            db.commit()
            flash('Account created successfully! Please log in.')
            return redirect('/login')
        except:
            flash('Username already taken. Try again.', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash(f"Welcome back, {username}!")
            return redirect('/')
        else:
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    if 'user_id' not in session:
        return redirect('/login')

    cursor = db.cursor()

    if request.method == 'POST':
        task = request.form['task']
        due_date = request.form['due_date']
        priority = request.form['priority']
        cursor.execute(
            "INSERT INTO tasks (user_id, content, due_date, priority) VALUES (%s, %s, %s, %s)",
            (session['user_id'], task, due_date, priority)
        )
        db.commit()
        flash('Task added successfully!')

    filter_by = request.args.get('filter', 'all')
    if filter_by == 'completed':
        cursor.execute("SELECT id, content, due_date, priority, completed FROM tasks WHERE user_id=%s AND completed=1", (session['user_id'],))
    elif filter_by == 'incomplete':
        cursor.execute("SELECT id, content, due_date, priority, completed FROM tasks WHERE user_id=%s AND completed=0", (session['user_id'],))
    else:
        cursor.execute("SELECT id, content, due_date, priority, completed FROM tasks WHERE user_id=%s", (session['user_id'],))

    user_tasks = cursor.fetchall()
    return render_template('tasks.html', tasks=user_tasks)

@app.route('/complete/<int:task_id>')
def complete_task(task_id):
    if 'user_id' in session:
        cursor = db.cursor()
        cursor.execute("UPDATE tasks SET completed=1 WHERE id=%s AND user_id=%s", (task_id, session['user_id']))
        db.commit()
    return redirect('/tasks')

@app.route('/delete/<int:task_id>')
def delete_task(task_id):
    if 'user_id' in session:
        cursor = db.cursor()
        cursor.execute("DELETE FROM tasks WHERE id=%s AND user_id=%s", (task_id, session['user_id']))
        db.commit()
    return redirect('/tasks')

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        return redirect('/login')

    cursor = db.cursor()
    if request.method == 'POST':
        content = request.form['content']
        due_date = request.form['due_date']
        priority = request.form['priority']
        cursor.execute(
            "UPDATE tasks SET content=%s, due_date=%s, priority=%s WHERE id=%s AND user_id=%s",
            (content, due_date, priority, task_id, session['user_id'])
        )
        db.commit()
        return redirect('/tasks')

    cursor.execute("SELECT id, content, due_date, priority, completed FROM tasks WHERE id=%s AND user_id=%s",
                   (task_id, session['user_id']))
    task = cursor.fetchone()
    return render_template('edit_task.html', task=task)

@app.route('/incomplete/<int:task_id>')
def mark_incomplete(task_id):
    if 'user_id' in session:
        cursor = db.cursor()
        cursor.execute("UPDATE tasks SET completed=0 WHERE id=%s AND user_id=%s", (task_id, session['user_id']))
        db.commit()
    return redirect('/tasks')

if __name__ == '__main__':
    app.run(debug=True)
