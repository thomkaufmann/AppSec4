from flask import Flask, flash, session, render_template, redirect, url_for, request
import sqlite3 as sql
import subprocess, random
import os, datetime
from subprocess import check_output
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, Regexp, Length, NumberRange, Optional
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint, ForeignKey

def create_app():

   sql.connect("database.db")
   project_dir = os.path.dirname(os.path.abspath(__file__))
   database_file = "sqlite:///{}".format(os.path.join(project_dir, "database.db"))

   app = Flask(__name__)

   app.config.update(
      SESSION_COOKIE_SECURE=False, # should be set to true upon adding SSL
      SESSION_COOKIE_HTTPONLY=True,
      SESSION_COOKIE_SAMESITE='Strict',
      TESTING=True,
      SECRET_KEY=os.urandom(16),
      SQLALCHEMY_DATABASE_URI = database_file,
      SQLALCHEMY_TRACK_MODIFICATIONS = False
   )
   db = SQLAlchemy(app)

   class User(db.Model):
      id = db.Column('id', db.Integer, primary_key = True)
      username = db.Column(db.String(50), unique = True)
      password = db.Column(db.String(100))  
      pin = db.Column(db.Integer)
      admin = db.Column(db.Boolean, default = False, nullable = False)

      def __init__(self, username, password, pin, admin):
         self.username = username
         self.password = generate_password_hash(password)
         self.pin = pin 
         self.admin = admin

   class Submission(db.Model):
      id = db.Column('id', db.Integer, primary_key = True)
      user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
      text = db.Column(db.String(500))
      result = db.Column(db.String(500))

      def __init__(self, user_id, text, result):
         self.user_id = user_id
         self.text = text
         self.result = result 

   class Log(db.Model):
      id = db.Column('id', db.Integer, primary_key = True)
      user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
      login = db.Column(db.DateTime)
      logout = db.Column(db.DateTime)

      def __init__(self, user_id, login, logout):
         self.user_id = user_id
         self.login = login
         self.logout = logout 

   db.create_all()
   admin = User.query.filter_by(username='admin').first()
   if admin is None:
      with open(os.environ['ADMIN_CREDENTIALS'], 'r') as f:   
         admin_password=f.readline().strip() 
         admin_pin=f.readline().strip()
         db.session.add(User('admin',admin_password,admin_pin,True))
         db.session.commit()
      
   @app.after_request
   def set_headers(response):
      response.headers['Content-Security-Policy'] = "default-src 'self'"
      response.headers["X-Frame-Options"] = "SAMEORIGIN"
      response.headers['X-Content-Type-Options'] = 'nosniff'
      response.headers['X-XSS-Protection'] = '1; mode=block'      
      return response

   @app.route("/")
   def index():
      #if logged in, send to spell check form, otherwise send to login
      if 'user_id' in session: 
         return redirect(url_for('spell_check'))
      
      return redirect(url_for('login'))

   @app.route('/login_history', methods = ['POST', 'GET'])
   def login_history():
      if 'user_id' in session:
         form = LoginHistoryForm()
         user = User.query.filter_by(id=session['user_id']).first()
         if user.admin: 
            logs = None
            if form.validate_on_submit():
               user = User.query.filter_by(id=form.user_id.data).first()
               logs = Log.query.filter_by(user_id=form.user_id.data).all()
            return render_template("login_history.html", form = form, logs = logs, user = user)

      return redirect(url_for('login'))

   @app.route("/history", defaults={"query":None}, methods = ['POST', 'GET'])
   @app.route("/history/<query>")
   def history(query):
      if 'user_id' in session:
         form = HistoryForm()
         user = User.query.filter_by(id=session['user_id']).first()     
         if query != None:
            submission_id = int(query.replace("query",""))
            #if user is admin, allow access to any submission by not filtering on user id
            if user.admin:
               submission = Submission.query.filter_by(id=submission_id).first()   
               user = User.query.filter_by(id=submission.user_id).first()
            else:
               submission = Submission.query.filter_by(user_id=session['user_id'], id=submission_id).first()   
            if submission is None:
               flash("Sorry, that submission doesn't exist", "failure")
            return render_template("submission.html", submission = submission, user = user)
         else:
            if user.admin and form.validate_on_submit():
                  submissions = Submission.query.join(User).filter_by(username=form.uname.data).all()
                  count = Submission.query.join(User).filter_by(username=form.uname.data).count()
            else:
               submissions = Submission.query.filter_by(user_id=session['user_id']).all()
               count = Submission.query.filter_by(user_id=session['user_id']).count()
            
            return render_template("history.html", submissions = submissions, count = count, user = user, form = form)
      else:
         return redirect(url_for('login'))         

   @app.route("/spell_check", methods = ['POST', 'GET'])
   def spell_check():
      if 'user_id' in session: 
         form = SpellForm()
         if form.validate_on_submit():
            text = form.inputtext.data
            #set textout field to be input text
            form.textout.data = form.inputtext.data
            form.inputtext.data = ""
            
            #define filename to include user_id and a random number
            user_id = session['user_id']
            filename = str(user_id)+'-'+str(random.randint(1, 1000))+'.txt'

            #create file and set output of check_words to misspelled input text
            with open(filename, 'w') as f:
               f.write(str(text))
               f.close()
               if os.path.isfile(filename):
                  form.misspelled.data = check_words(filename)
                  os.remove(filename)
                  submission = Submission(user_id, text, form.misspelled.data)
                  db.session.add(submission)
                  db.session.commit() 
               else:
                  print("Error: %s file not found" % filename)            

         return render_template("spell_check.html", form = form)
      else:
         return redirect(url_for('login'))

   @app.route('/register', methods = ['POST', 'GET'])
   def register():
      if 'user_id' in session: 
         return redirect(url_for('spell_check'))

      form = UserForm()
      # form_type is used to put a title on the html view and to set the form action (register or login)
      form_type = "Register"

      if request.method == "POST":
         if form.validate_on_submit():
            username = form.uname.data
            password = form.pword.data
            pin = form.pin.data
            admin = False

            if username != '' and password != '' and pin != '':
               user = User.query.filter_by(username=username).first()
               if user != None:
                  flash("Failure: Account already exists. Please login or select a different username.","success")
                  return redirect(url_for('login'))  
               else:
                  user = User(username, password, pin, admin)
                  db.session.add(user)
                  db.session.commit()                     
                  flash("Success: Account registered!","success")
                  return redirect(url_for('login'))  
            else:
               flash("Failure: Invalid account details. Please try again.","success")
         else:   
            flash("Failure: Please try again.","success")

      return render_template("form.html", type = form_type, form = form)

   @app.route('/login', methods = ['POST', 'GET'])
   def login():
      if 'user_id' in session: 
         return redirect(url_for('spell_check'))
      
      form = UserForm()
      # form_type is used to put a title on the html view and to set the form action (register or login)
      form_type = 'Login'
      if request.method == 'POST':
         if form.validate_on_submit():
            
            username = form.uname.data
            password = form.pword.data
            pin = form.pin.data
            
            user = User.query.filter_by(username=username).first()

            if user != None and check_password_hash(user.password,password):
               if (pin == user.pin) or (pin == "" and user.pin is None):
                  session['user_id'] = user.id
                  session['admin'] = user.admin
                  log = Log(session['user_id'], datetime.datetime.now() , None)
                  db.session.add(log)
                  db.session.commit()
                  session['log_id'] = log.id
                  flash("Success: You are logged in!","result")
                  return redirect(url_for('spell_check'))                              
               else:
                  flash("Two-factor failure. Please try again.","result")   
            else:
               flash("Incorrect username or password. Please try again.","result")
         else:
            flash("Failure: Please try again.","result")

      return render_template("form.html", type = form_type, form = form)      

   @app.route('/logout')
   def logout():
      if 'log_id' in session:
         log = Log.query.filter_by(id=session['log_id']).first()
         log.logout = datetime.datetime.now()
         db.session.commit()
      session.clear()
      return redirect(url_for('login'))

   def check_words(filename):
      stdout = check_output(['./a.out',filename, 'wordlist.txt']).decode('utf-8').replace('\n',', ')[:-2]
      return stdout

   class LoginHistoryForm(FlaskForm):
      user_id = IntegerField('User ID', validators=[InputRequired()], id='userid')
      submit = SubmitField('Submit')

   class HistoryForm(FlaskForm):
      uname = StringField('Username', validators=[InputRequired(), Regexp(r'^[\w.@+-]+$'), Length(min=4, max=25)], id='userquery')
      submit = SubmitField('Submit')
      
   class UserForm(FlaskForm):
      uname = StringField('Username', validators=[InputRequired(), Regexp(r'^[\w.@+-]+$'), Length(min=4, max=25)])
      pword = PasswordField('Password', validators=[InputRequired()])
      pin = IntegerField('Two-Factor Authentication', validators=[Optional(), NumberRange(min=1000000000,max=99999999999)], id='2fa')
      submit = SubmitField('Submit')

   class SpellForm(FlaskForm):
      inputtext = TextAreaField('Text', validators=[InputRequired()], id="inputtext", render_kw={"rows": 4, "cols": 100})
      textout = TextAreaField('Text out', id="textout", render_kw={"disabled": "disabled", "rows": 4, "cols": 100})
      misspelled = TextAreaField('Misspelled', id="misspelled", render_kw={"disabled": "disabled", "rows": 4, "cols": 100})
      submit = SubmitField('Submit')

   return app
if __name__ == '__app__':
   create_app().run(debug = True)