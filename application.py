from crypt import methods
from random import randint
from ast import And
from email import message
from random import randint
from flask import Flask, url_for, render_template, request, redirect, session, json
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, UserMixin
from sqlalchemy import false
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin , AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_recaptcha import ReCaptcha
from flask_wtf import RecaptchaField
from flask_mail import *
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

application = Flask(__name__)
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(application)
recaptcha = ReCaptcha(application=application)



'''
application.config['MAIL_SERVER ']='smtp.gmail.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_USERNAME'] = params['gmail-user']
application.config['MAIL_PASSWORD'] = params['gmail-pass']
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
'''


application.config.update(dict(
    RECAPTCHA_ENABLED = True,
    RECAPTCHA_SITE_KEY = "6LcaCiUeAAAAAE8c5Eb3ADVw-7UPybPHppPl7kpv",
    RECAPTCHA_SECRET_KEY = "6LcaCiUeAAAAAI5X0blM8ghaB4mzElzJa9hHQw5p",
    ))
 
recaptcha = ReCaptcha()
recaptcha.init_app(application)
#recaptcha.init_application(application)




class User(UserMixin ,db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100))
    lname = db.Column(db.String(100))
    email = db.Column(db.String(100), primary_key=True)
    password = db.Column(db.String(100))

    def __init__(self, fname, lname, email, password):
        self.fname = fname
        self.lname = lname
        self.email = email
        self.password = password


@application.route('/', methods=['GET','POST'])
def index():
    if session.get('logged_in'):
        #user=session['user']
        return redirect(url_for('home'))
    else:
        return render_template('index.html', message="Hello!")


@application.route('/home/',methods=['GET','POST'])
def home():
    return render_template('home.html')
'''
@application.route('/email/',methods=['GET','POST'])
def email():
    return render_template('email.html')
'''
'''
@application.route('/verify', methods=['GET','POST'])
def verify():
    mails = request.form['email']
    msg = Message('OTP', sender='devnpatel18@gnu.ac.in', recipients=[mails])
    msg.body= str(otp)
    mail.send(msg)
    return render_template('verify.html')
'''








@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            password, cnfpassword=request.form['password'], request.form['cnfpassword']
            if(password==cnfpassword):
                db.session.add(User(fname=request.form['fname'], lname=request.form['lname'], email=request.form['email'], password=generate_password_hash(password, method='sha256')))
                db.session.commit()
                return redirect(url_for('login'))
            else:
                return render_template('index.html', message="Please confirm proper password")
        except:
            return render_template('index.html', message="User Already Exists")
    else:
        return render_template('register.html')

application.config.from_pyfile('config.cfg')

mail = Mail(application)
otp = randint(0000, 9999)
s = URLSafeTimedSerializer('Thisisasecret!')

@application.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'GET':
        return render_template('login.html')
    else:
        email = request.form['email']
        password = request.form['password']
        

        data = User.query.filter_by(email=email).first()


        if (data and check_password_hash(data.password, password)) and recaptcha.verify():
            msg = Message('Confirm Email', sender='devnpatel18@gnu.ac.in', recipients=[email])
            msg.body = str(otp) #'Your link is {}'.format(link)
            mail.send(msg)
            return redirect('/confirm')
            #session['logged_in'] = True
            #return redirect(url_for('index'))
        elif(data==None):
            return render_template('login.html',message="Email is not registered")
        elif not (data and check_password_hash(data.password, password)):
            return render_template('login.html',message="Email and password don't match")
    
        return render_template('login.html', message="Recheck the Field") 


@application.route('/logout', methods=['GET', 'POST'])
def logout():
    #session['logged_in'] = False
    return redirect(url_for('index'))


'''
@application.route('/em', methods=['GET', 'POST'])
def indexs():
    if request.method == 'GET':
        return render_template('email.html')
    #    return '<form action="/em" method="POST"><input name="email"><input type="submit"></form>'

    email = request.form['email']
    #token = s.dumps(email, salt='email-confirm')

    msg = Message('Confirm Email', sender='devnpatel18@gnu.ac.in', recipients=[email])

    #link = url_for('confirm_email', token=token, _external=True)

    msg.body = str(otp) #'Your link is {}'.format(link)

    mail.send(msg)

    return redirect('/confirm')

    #return '<h1>The email you entered is {}.</h1>'.format(email) 
'''
@application.route('/confirm', methods=['GET', 'POST'])
def confirm():
    if request.method == 'GET':
        return render_template('verify.html')
     #   return '<form action="/confirm" method="POST"><input name="otp"><input type="submit"></form>'

    userotp=request.form['otp']
    if otp== int(userotp):
        #session['logged_in'] = True
        #return redirect(url_for('index'))
        return render_template('home.html')
        #return " Email verified Success" 
    return redirect('/confirm')

admin = Admin(application)
admin.add_view(ModelView(User, db.session))


if(__name__ == '__main__'):
    application.secret_key = "ThisIsNotASecret:p"
    db.create_all()
    application.debug = 1
    application.run()