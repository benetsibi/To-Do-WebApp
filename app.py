from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/ToDo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'super_secret_key' 

db = SQLAlchemy(app)

#  Database 
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
    # These relationships define how we access tasks
    tasks_assigned_to_me = db.relationship('Task', foreign_keys='Task.assigned_to', backref='assignee', lazy=True)
    tasks_i_created = db.relationship('Task', foreign_keys='Task.created_by', backref='creator', lazy=True)

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

#  Routes

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    other_users = User.query.filter(User.id != session['user_id']).all()
    
   
    my_tasks = current_user.tasks_assigned_to_me
    created_tasks = current_user.tasks_i_created
    
    return render_template('dashboard.html', 
                           user=current_user, 
                           other_users=other_users, 
                           my_tasks=my_tasks, 
                           created_tasks=created_tasks)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
        
            session['user_id'] = new_user.id 
            return redirect(url_for('index'))
            
        except Exception as e:
            db.session.rollback()
            return f"Error: {str(e)}", 400
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        
        return "Invalid credentials", 401
        
    return render_template('login.html')

@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('content')
    assignee_id = request.form.get('assignee_id')
    
    
    if assignee_id == "none" or not assignee_id:
        assignee_id = None

    new_task = Task(content=content, assigned_to=assignee_id, created_by=session['user_id'])
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/reassign_task/<int:task_id>', methods=['POST'])
def reassign_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    task = Task.query.get_or_404(task_id)
    
    
    if task.created_by != session['user_id']:
        return "Unauthorized", 403
        
    new_assignee_id = request.form.get('new_assignee_id')
    task.assigned_to = None if new_assignee_id == "none" else new_assignee_id
    
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)