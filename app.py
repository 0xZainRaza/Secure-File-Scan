from flask import Flask, render_template, redirect, url_for , flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_manager, login_required, logout_user , current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField ,FileField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask import session
from sqlalchemy import desc
import os
from datetime import datetime
import hashlib
import requests
import subprocess
import logging 
import random
import string


logging.basicConfig(filename='log.log', level=logging.DEBUG, format='%(asctime)s [%(levelname)s] - %(message)s')


app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configuration
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///base.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable Flask-SQLAlchemy modification tracking
app.config['UPLOAD_FOLDER'] = 'static/files'

app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'smartpakingsystem@outlook.com'
app.config['MAIL_PASSWORD'] = 'parkingsystemsecurepassword1234'

mail = Mail(app)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")




# Database Model
class Company(db.Model):
    company_id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(20), nullable=False)
    users = db.relationship('User', back_populates='company')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.company_id'), nullable=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    # Define the relationship between Users and Company
    company = db.relationship('Company', back_populates='users')
    reports = db.relationship('Report', back_populates='user')


class Category(db.Model):
    category_id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(20),nullable = False)
    malware = db.relationship('Malware', back_populates='category')


class Malware(db.Model):
    malware_id = db.Column(db.Integer, primary_key=True)
    malware_name = db.Column(db.String(20), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.category_id'),nullable=False)
    malware_hash = db.Column(db.String(200),nullable = False)
    malware_target_system = db.Column(db.String(20),nullable = False)
    yara_rule = db.Column(db.String(2000),nullable = False)
    description = db.Column(db.String(2000),nullable = False)

    category = db.relationship('Category', back_populates='malware')
    reports = db.relationship('Report', back_populates='malware')

class Report(db.Model):
    report_id = db.Column(db.Integer, primary_key=True)
    malware_id = db.Column(db.Integer,db.ForeignKey('malware.malware_id'), nullable=False)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'), nullable=False)
    report_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    malware = db.relationship('Malware', back_populates='reports')
    user = db.relationship('User', back_populates='reports')


# Forms

class Malwareform(FlaskForm):
    Mname = StringField('Malware Name', validators=[InputRequired(), Length(min=2, max=20)])
    Mcategory = StringField('Malware Category', validators=[InputRequired(), Length(min=2, max=20)])
    Mtsystem = StringField('Malware target system', validators=[InputRequired(), Length(min=2, max=20)])
    Fhash = StringField('File hash', validators=[InputRequired(), Length(min=2, max=200)])
    Yrule = StringField('Yara rule', validators=[InputRequired(), Length(min=2, max=200000)])
    description = StringField('Enter description', validators=[InputRequired(), Length(min=2, max=2000)])

    submit = SubmitField('Submit')



class RegisterForm(FlaskForm):
    fname = StringField('First Name', validators=[InputRequired(), Length(min=2, max=20)])
    lname = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=20)])
    company = StringField('Company Name', validators=[InputRequired(), Length(min=2, max=20)])
    email = StringField('Email Address', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    cpassword = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match.')], render_kw={"placeholder": "Confirm Password"})

    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError('This Email has already been used.')

class LoginForm(FlaskForm):
    email = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

    submit = SubmitField('Login')

class VerificationForm(FlaskForm):
    Verificationcode = StringField('Code', validators=[InputRequired()])
    
    submit = SubmitField('Enter')



#functions

def generate_verification_code(length=20):
    characters = string.ascii_lowercase + string.digits
    verification_code = ''.join(random.choice(characters) for i in range(length))
    return verification_code

def send_verification_email(email, verification_code):
    msg = Message('Verification Code', sender='smartpakingsystem@outlook.com', recipients=[email])
    msg.body = f'Your verification code is: {verification_code}'
    mail.send(msg)


def get_virus_total_info(md5_hash):
    url = "https://www.virustotal.com/api/v3/files/" + md5_hash
    headers = {
        "accept": "application/json",
        "x-apikey": "dfd694fbbcb54137fbf56f021859ef91559633f96bfeee088f6c8fbc353035bf"
    }
    response = requests.get(url, headers=headers)
    return response.json()

def calculate_md5_hash(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096000), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def calculate_sha256_hash(file_path):
    # Calculate SHA256 hash of the file
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096000), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_malware_bazaar_info(sha256_hash):
    # Implementation of Malware Bazaar API call
    response = requests.post(
        url="https://mb-api.abuse.ch/api/v1/",
        data={
            "query": "get_info",
            "hash": sha256_hash
        }
    )
    return response.json()





# Database Initialization
with app.app_context():
    db.create_all()

# Login Manager User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes

@app.route('/results/<filename>')
# def results(filename):
#     return render_template('results.html', filename=filename)
def results(filename):
    # Calculate MD5 hash of the uploaded file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    md5_hash = md5_hash = calculate_md5_hash(file_path)
    # Calculate SHA256 hash of the uploaded file
    sha256_hash = calculate_sha256_hash(file_path)
    # Call the VirusTotal API
    # Call the VirusTotal API
    # Call the VirusTotal API
    virus_total_info = get_virus_total_info(md5_hash)

# Check if 'data' key exists
    if 'data' in virus_total_info:
        data = virus_total_info['data']
    # Check if 'attributes' key exists
        if 'attributes' in data:
            attributes = data['attributes']
            # Check if 'crowdsourced_yara_results' key exists
            crowd_results = attributes.get('crowdsourced_yara_results', None)

        # Check if 'crowdsourced_yara_results' is a list or iterable
            if crowd_results and isinstance(crowd_results, list):
                # Continue processing with the rest of your code
                for result in crowd_results:
                # Your processing logic for each 'result'
                    pass
            else:
            # Handle the case where 'crowdsourced_yara_results' is not present or not a list
                return redirect(url_for('noresults'))
        else:
        # Handle the case where 'attributes' key is not present
            return redirect(url_for('noresults'))
    else:
    # Handle the case where 'data' key is not present
        return redirect(url_for('noresults'))






    rule_name = []
    author = []
    source = []
    ruleset_name = []
    description = []
    type_description = virus_total_info["data"]["attributes"]["type_description"]
    type_tags = []
    names = []





    for result in virus_total_info['data']['attributes']['crowdsourced_yara_results']:
        rule_name.append(result.get('rule_name', 'N/A'))
        author.append(result.get('author', 'N/A'))
        source.append(result.get('source', 'N/A'))
        ruleset_name.append(result.get('ruleset_name','N/A'))
        description.append(result.get('description','N/A'))
    

    for tag in virus_total_info['data']['attributes']['type_tags']:
        type_tags.append(tag)

    for name in virus_total_info['data']['attributes']['names']:
        names.append(name)


    print(f"Rule Name: {rule_name}")
    print(f"Author: {author}")
    print(f"Source: {source}")
    print("-" * 50)
    name_len = len(names)
    length = len(rule_name)
    tag_length = len(type_tags)
    #print(virus_total_info)
    print("________________________________________GOIN INTO THE DEEP_________________________________________________")

    # Malware Bazaar's shit;
    malware_bazaar_info = get_malware_bazaar_info(sha256_hash)

    print(malware_bazaar_info)
    malware_instance = Malware.query.filter_by(malware_hash=sha256_hash).first()

    if malware_instance:
        print(malware_instance.malware_name)
    else:
        print("Malware not found for the given yara_rule.")


    return render_template('results2.html',names=names,name_len=name_len,tag_length=tag_length,type_tags=type_tags,type_description=type_description,description1=description,ruleset_name=ruleset_name ,filename=filename, virus_total_info=virus_total_info, malware_bazaar_info=malware_bazaar_info
                           ,malware_name=malware_instance.malware_name,malware_hash=malware_instance.malware_hash,Target=malware_instance.malware_target_system
                           ,rule = malware_instance.yara_rule,description = malware_instance.description, rule_name = rule_name, author = author, source = source, length = length)





@app.route('/noresults')
def noresults():
    return render_template('no malware.html')


@app.route('/deleteacount')
@login_required
def deleteacount():
    # Delete the user and related records
    user_id = current_user.id
    user = User.query.get(user_id)

# Delete user-related records (e.g., reports)
    Report.query.filter_by(user_id=user_id).delete()

# Delete the user
    db.session.delete(user)
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

    




@app.route('/updatereport')
@login_required
def updatereport():
    form = Malwareform()

    # Get the most recent report for the current user
    user_reports = Report.query.filter_by(user_id=current_user.id).order_by(desc(Report.report_date)).first()

    if user_reports:
        # Access the associated Malware object to get malware_name and other attributes
        malware_instance = user_reports.malware

        # Extract attributes from the Malware instance
        malware_name = malware_instance.malware_name
        malware_category = malware_instance.category.category
        hash = malware_instance.malware_hash
        malware_target_system = malware_instance.malware_target_system
        yara_rule = malware_instance.yara_rule
        description = malware_instance.description

        # Pass the form, user's reports, and extracted attributes to the template
        return render_template('updatereport.html', form=form,hash=hash, malware_category=malware_category, user_reports=user_reports, malware_name=malware_name,
                               malware_target_system=malware_target_system, yara_rule=yara_rule, description=description)
    else:
        print("No reports found for the current user.")

    # If there are no reports, still pass the form to the template
    return render_template('updatereport.html', form=form)




@app.route('/verification', methods=['GET', 'POST'])
def verification():
    form = VerificationForm()

    if form.validate_on_submit():
        # Get stored verification code from session
        stored_verification_code = session.get('verification_code')
        # Get entered verification code from form
        entered_verification_code = form.Verificationcode.data
        # Compare entered code with stored code
        if stored_verification_code == entered_verification_code:
            # Verification successful, proceed with desired action
            # For example, log the user in
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template('verification.html', form=form)

    

    





from sqlalchemy.exc import IntegrityError

@app.route('/updatesignature', methods=['GET', 'POST'])
@login_required
def updatesignature():  
    form = Malwareform()

    if form.validate_on_submit():
        # Check if the category already exists
        existing_category = Category.query.filter_by(category=form.Mcategory.data).first()

        if existing_category:
            category_id = existing_category.category_id
        else:
            # Create a new category if it doesn't exist
            new_category = Category(category=form.Mcategory.data)

            try:
                db.session.add(new_category)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash('Category creation failed. Please try again.', 'danger')
                return redirect(url_for('updatesignature'))

            category_id = new_category.category_id

        

        new_malware = Malware(
            malware_name=form.Mname.data,
            category_id=category_id,
            malware_target_system=form.Mtsystem.data,
            malware_hash=form.Fhash.data,
            yara_rule=form.Yrule.data,
            description=form.description.data
        )

        try:
            db.session.add(new_malware)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Malware creation failed. Please try again.', 'danger')
            return redirect(url_for('updatesignature'))

        new_report = Report(
            malware_id=new_malware.malware_id,
            user_id=current_user.id,
            report_date=datetime.utcnow()
        )

        try:
            db.session.add(new_report)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Report creation failed. Please try again.', 'danger')
            return redirect(url_for('updatesignature'))

        flash('Malware signature updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    else:
        print("Form validation failed:", form.errors)

    return render_template('form.html', form=form)



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_company = Company(company_name=form.company.data)
        db.session.add(new_company)
        db.session.commit()

        company_id = new_company.company_id

        new_user = User(
            firstname=form.fname.data,
            lastname=form.lname.data,
            company_id=company_id,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    else:
        print("Form validation failed:", form.errors)

    return render_template('registration.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # Generate random verification code
            verification_code = generate_verification_code()
            # Store verification code in session
            session['verification_code'] = verification_code
            # Send verification email
            send_verification_email(user.email, verification_code)
            # Redirect to verification page
            return redirect(url_for('verification'))
        else:
            flash('Invalid Username or Password. Please try again.', 'danger')

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user_first_name = current_user.firstname
    reports_data = db.session.query(
        Malware.malware_name,
        Malware.malware_target_system,
        Company.company_name,  
        Report.report_date
    ).select_from(Report) \
    .join(User).join(Company).join(Malware).order_by(Report.report_date.desc()).all()
    return render_template('dashboard.html' , user_first_name=user_first_name,reports_data=reports_data)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    form = UploadFileForm()
    malware_instance = None  # Use a different name for the variable

    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)), app.config['UPLOAD_FOLDER'], secure_filename(file.filename)))
        return redirect(url_for('results', filename=filename))

    return render_template('index.html', form=form)


if __name__ == "__main__":
    app.run(debug=True,ssl_context=('cert.pem', 'key.pem'),port=5555)
