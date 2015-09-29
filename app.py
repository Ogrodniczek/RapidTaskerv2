#!/usr/bin/python
# -*-coding:utf-8-*-
# TO RUN TYPE: python app.py runserver

# =============== IMPORT LIST ===============
# Defined in requirements.txt
# Installation: pip install -r requirements.txt
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   url_for,
                   session,
                   )
from flask.ext.login import (LoginManager,
                             login_user,
                             logout_user,
                             login_required,
                             current_user,
                             )
from flask.ext.script import Manager
from flask.ext.bootstrap import Bootstrap
from flask.ext.sqlalchemy import SQLAlchemy
from form_objects.login import LoginForm
from form_objects.new_task import NewTaskForm
from pprint import pprint
import datetime
import os
import ldap
import bbcode

# =============== CONFIGURATION ===============
app = Flask(__name__)
app.debug = True
manager = Manager(app)
bootstrap = Bootstrap(app)

# SQL Alchemy configuration
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite://{0}/tasker.db'.format(os.path.dirname(__file__))
db = SQLAlchemy(app)

# Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# LDAP configuration
LDAP_SERVER = ""    # LDAP server address
# DC = ""       # LDAP Domain Component

# =============== MODELS ===============
class User(db.Model):
    '''
        id:                 unique user ID
        username:           username from LDAP server database
        tasks_requested:    tasks that user requested
        tasks_claimed:      tasks that user claimed
    '''
    __tablename__   = 'users'
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(64), unique=True, index=True)
    tasks_requested = db.relationship("Task", 
                            backref="requestor",
                            foreign_keys='Task.requestor_id')
    tasks_claimed   = db.relationship("Task", 
                            backref="claimer",
                            foreign_keys='Task.claimer_id')

    def __repr__(self):
        return self.username

    def is_active(self):
        return True

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

class Task(db.Model):
    '''
        id:                 unique user ID
        create_date:        timestamp of task creation
        last_update_date:   timestamp of last modification ('done' is the last modification)
        title:              task title (max 255 chars)
        description:        task description (max 2000 chars with BBCode)
        severity:           priority of task [range 1-5 (1-highest, 5-lowest)]
        claimer:            id of user who claimed the task
        requestor:          id of user who requested the task
        state:              current state of the task (possible values: 'todo','ongoing','done')
    '''
    __tablename__       = 'tasks'
    id                  = db.Column(db.String(8), primary_key=True)
    create_date         = db.Column(db.String(30))
    last_update_date    = db.Column(db.String(30))
    title               = db.Column(db.String(255), unique=True)
    description         = db.Column(db.String(2000))
    severity            = db.Column(db.Integer, default='3')
    claimer_id          = db.Column(db.Integer, db.ForeignKey('users.id'))
    requestor_id        = db.Column(db.Integer, db.ForeignKey('users.id'))
    state               = db.Column(db.String(60))

    def __unicode__(self):
        return self.id

# =============== METHODS ===============
def init_db():
    '''
        Database initializer
    '''
    db.create_all(app=app)

@app.route('/')
@login_required
def index():
    '''
        Main tasks viewing and submitting page.
        Returns form for creating new tasks and list of all tasks.
        Tasks are sorted by last update date.
        ----
        Login required to access.
    '''
    form = NewTaskForm(request.form, csrf_enabled=False)
    tasks = Task.query.order_by(Task.last_update_date.desc()).all()
    return render_template('index.html', form=form, tasks=tasks)

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
        Login page.
        Connected to LDAP server.
        Enter valid LDAP server config at configuration section.
        
        After successful LDAP logging if user with given username exists in our database, he is logged with Flask-Login function.
        If there is no user with given username in our database new one is created and logged with Flask-Login function. 

        WARNING!
        There is no information regarding invalid credentials.
        Login page is not brute-force resistant!
    '''
    ld = ldap.open(LDAP_SERVER)
    ld.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    ld.set_option(ldap.OPT_REFERRALS, 0)
    form = LoginForm(request.form, csrf_enabled=False)
    if form.validate_on_submit():
        try:
            ld.simple_bind_s("uid="+request.form['username'],request.form['password'])
            if User.query.filter_by(username=request.form['username']).first():
                user = User.query.filter_by(username=request.form['username']).first()
            else:
                user = User(username=request.form['username'])
                db.session.add(user)
                db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        except ldap.INVALID_CREDENTIALS:
            pass
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    '''
        Logout current user and redirect him to login page.
        ----
        Login required to access.
    '''
    logout_user()
    return redirect(url_for('index'))

@app.route('/new_task', methods=['GET', 'POST'])
@login_required
def new_task():
    '''
        Create a new task with model given in MODEL section.
        Each new task is given a random number that identifies it.
        Adding a creation timestamp which is uneditable.
        Adding an update timestamp which at creation is same as creation timestamp.
        Title and severity contents are taken from form.
        Description content can be enriched with BBCode tags 
            (see: http://bbcode.readthedocs.org/en/latest/tags.html for details).
        Requestor_id is id of currently logged user.
        Default state of newly created task is 'to do'.
        ----
        Login required to access.
    '''
    form = NewTaskForm(request.form, csrf_enabled=False)
    if form.validate_on_submit():
        db.session.add(
            Task(
                id=str(os.urandom(4).encode('hex')),
                create_date=datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"),
                last_update_date=datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"),
                title=request.form['title'],
                description=bbcode.render_html(request.form['description']),
                severity=request.form['priority'],
                requestor_id=current_user.get_id(),
                state='to do',
            )
        )
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_task', methods=['POST'])
@login_required
def delete_task():
    '''
        Deletion of task.
        Can only be done by the creator of the task.

        WARNING!
        There is no prompt for confirmation or backup of the task.
        ----
        Login required to access.
    '''
    task = Task.query.filter_by(id=request.form['task_id']).first()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/modify_task', methods=['POST'])
@login_required
def modify_task():
    '''
        Possible status modifications:
            TO DO   ---> ONGOING  - task is claimed by somebody (current user_id as claimer_id)
            ONGOING ---> TO DO    - task is unclaimed by claimer (claimer_id is cleared)
            ONGOING ---> DONE     - task is completed by claimer 

        Whenever there is a modification to the status, last_update_date is updated with current timestamp.    
        ----
        Login required to access.
    '''
    task = Task.query.filter_by(id=request.form['task_id'])
    task.update({'state': request.form['task_state']})
    task.update({'claimer_id': request.form['task_claimer']})
    task.update({'last_update_date': datetime.datetime.now(). \
            strftime("%Y-%m-%d %H:%M:%S")})
    db.session.commit()
    return redirect(url_for('index'))

@login_manager.user_loader
def load_user(userid):
    '''
        Used by LoginManager. Mandatory.
    '''
    return User.query.get(userid)

@app.route('/filter_by/<key>/<value>')
@login_required
def filter_by(key, value):
    '''
        Tasks filtering function.
        Possible filters:
            by state: all tasks with state 'to do', 'ongoing' or 'done'
            by priority: all tasks with priority: 1, 2, 3, 4 or 5)
            all tasks claimed by current user   
            all tasks requested by current user
            all not claimed tasks

        All filtered results are sorted by last update date.
        It is not possible to sort filtered results.
        ----
        Login required to access
    '''
    
    form = NewTaskForm(request.form, csrf_enabled=False)
    if key == 'state':
        tasks = Task.query.filter_by(state=value).order_by(Task.last_update_date.desc()).all()
    elif key == 'priority':
        tasks = Task.query.filter_by(severity=value).order_by(Task.last_update_date.desc()).all()
    elif key == 'requestor' and value == 'me':
        tasks = Task.query.filter_by(requestor_id=current_user.get_id()).order_by(Task.last_update_date.desc()).all()
    elif key == 'claimer' and value == 'me':
        tasks = Task.query.filter_by(claimer_id=current_user.get_id()).order_by(Task.last_update_date.desc()).all()
    else:
        tasks = Task.query.filter_by(claimer_id=None).order_by(Task.last_update_date.desc()).all()
    return render_template('index.html', form=form, tasks=tasks)

@app.route('/sort_by/<sorter>/<reverse>')
@login_required
def sort(sorter, reverse):
    '''
        Tasks sorting function.
        Possible sorter values: 
            'state'         returns all tasks sorted by state 
            'severity'      returns all tasks sorted by priority
            'timestamp'     returns all tasks sorted by date of creation
        If reverse value is '1' tasks are sorted descending. Else tasks are sorted ascending.

        It is not possible to filter sorted tasks.
        ----
        Login required to access
    '''
    form = NewTaskForm(request.form, csrf_enabled=False)
    all_tasks = Task.query
    if sorter == "severity":
        if reverse == "1":
            ordered_tasks = all_tasks.order_by(Task.severity.desc()).all()
        else:
            ordered_tasks = all_tasks.order_by(Task.severity).all()
    elif sorter == "timestamp":
        if reverse == "1":
            ordered_tasks = all_tasks.order_by(Task.create_date.desc()).all()
        else:
            ordered_tasks = all_tasks.order_by(Task.create_date).all()
    else:
        if reverse == "1":
            ordered_tasks = all_tasks.order_by(Task.state).all()
        else:
            ordered_tasks = all_tasks.order_by(Task.state.desc()).all()
    return render_template('index.html', form=form, tasks=ordered_tasks)

# =============== STARTER ===============
# This app uses Manager. Start the app server by typing: python app.py runserver
if __name__ == '__main__':
    init_db()
    manager.run()
