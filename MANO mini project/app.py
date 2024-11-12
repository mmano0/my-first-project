from flask import Flask, render_template, flash, redirect, request, url_for, session 

from passlib.hash import sha256_crypt,bcrypt
import random
from functools import wraps
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
from passlib.hash import sha256_crypt

# Hash and store the password during registration

app = Flask(__name__)
app.secret_key = 'some secret key'

# Config MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/bloodbank'
mongo = PyMongo(app)
# List all collections
print("Collections:")
for collection in mongo.db.list_collection_names():
    print(f"- {collection}")

# Access a specific collection
collection = mongo.db["donor"]

# Insert a document
new_document = {"blood_type": "A+", "blood_group": "RH+", "packets": 10}
collection.insert_one(new_document)

# Find a document
document = collection.find_one({"blood_type": "A+"})
print(f"Document found: {document}")

# Update a document
filter = {"blood_group": "RH+"}
update = {"$inc": {"packets": -5}}
collection.update_many(filter, update)

# Delete a document
filter = {"blood_type": "A-"}
collection.delete_many(filter)

# Ensure that the MongoDB connection is established successfully
if mongo:
    print('MongoDB connection established successfully')
else:
    print('Failed to establish MongoDB connection')


@app.route('/')
def index():
    return render_template('home.html')
# ... (Other routes and functions)

@app.route('/home1')
def home1():
    return render_template('home1.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/donornote')
def donornote():
    return render_template('donornote.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        bgroup = request.form['bgroup']
        bpackets = request.form['bpackets']
        fname = request.form['fname']
        address = request.form['address']

        # Insert data into MongoDB
        mongo.db.contact.insert_one({
            'B_GROUP': bgroup,
            'C_PACKETS': bpackets,
            'F_NAME': fname,
            'ADRESS': address
        })

        # Insert data into Notifications
        mongo.db.notifications.insert_one({
            'NB_GROUP': bgroup,
            'N_PACKETS': bpackets,
            'NF_NAME': fname,
            'NADRESS': address
        })

        flash('Your request is successfully sent to the Blood Bank', 'success')
        return redirect(url_for('index'))

    return render_template('contact.html')


# Register Form
class RegisterForm(FlaskForm):
    name = StringField('name', [validators.DataRequired(), validators.Length(min=1, max=25)])
    email = StringField('email', [validators.DataRequired(), validators.Length(min=10, max=50)])
    password = PasswordField('password', [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('cpassword')
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        donor_id = request.form['donor_id']
        blood_group = request.form['blood_group']
        address = request.form['address']
        city = request.form['city']
        contact_number = request.form['contact_number']
        email = request.form['email']
        password = request.form['password']
        cpassword = request.form['cpassword']

        # Insert data into MongoDB
        mongo.db.reception.insert_one({
            'name': name,
            'donor_id':donor_id ,
            'blood_group':blood_group,
            'address':address,
            'city':city,
            'contact_number':contact_number,
            'email': email,
            'password': password,
            'cpassword': cpassword
        })


        flash('Your request is successfully Register', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

    
@app.route('/layout', methods=['GET', 'POST'])
def layout():
    if request.method == 'POST':
        name = request.form['fullName']
        dob = request.form['dob']
        age = request.form['age']
        bloodGroup = request.form['bloodGroup']
        mobileNumber = request.form['mobileNumber']
        email = request.form['email']
        donationStatus = request.form['donationStatus']
        activities = request.form['activities[]']

        # Insert data into MongoDB
        mongo.db.donor.insert_one({
            'name': name,
            'donor_id': dob ,
            'age': age,
            'bloodGroup': bloodGroup,
            'mobileNumber': mobileNumber,
            'email': email,
            'donationStatus': donationStatus,
            'activities': activities
        })


        flash('Your request is successfully Register', 'success')
        return redirect(url_for('home1'))
    
    return render_template('layout.html')

# ... (Other routes and functions)


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form["email"]
        password_candidate = request.form["password"]

        # Get admin user from MongoDB
        user = mongo.db.admin.find_one({'email': email})

        if user:
            stored_password = user.get('password')

            if bcrypt.hashpw(password_candidate.encode('utf-8'), stored_password) == stored_password:
                session['logged_in'] = True
                session['email'] = email
                session['role'] = 'admin'
                flash('You are now logged in as admin', 'success')
                return redirect(url_for('admin'))
            else:
                error = 'Invalid password'
                return render_template('admin.html', error=error)
        else:
            error = 'Admin email not found'
            return render_template('admin.html', error=error)

    return render_template('admin.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form["email"]
        password_candidate = request.form["password"]

        # Get user from MongoDB
        user = mongo.db.reception.find_one({'email': email})

        if user:
            stored_password = user.get('password')

            if  stored_password == stored_password:
                session['logged_in'] = True
                session['email'] = email
                session['role'] = user.get('role')
                flash('You are now logged in as admin', 'success')
                return redirect(url_for('home1'))
            else:
                error = 'Invalid password'
                return render_template('login.html', error=error)
        elif password_candidate== 'admin' and email =='admin@gmail.com':
            flash('You are now logged in', 'success')
            return redirect(url_for('home1'))
       
        else:
            error = 'Email not found'
            return render_template('login.html', error=error)

    return render_template('login.html')
    

# ... (Other routes and functions)

# is_logged_in decorator
def logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login!', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard1')
@logged_in
def dashboard1():
    # Assuming your registration data is stored in the 'users' collection
    user_id = session.get('email')
    registration = mongo.db.reception.find_one({'email': user_id})
    # Assuming your donor data is stored in the 'donors' collection
    details = list(mongo.db.donor.find())

    return render_template('dashboard1.html', registration=registration, details=details)

@app.route('/dashboard')

def dashboard():
    # Assuming your registration data is stored in the 'users' collection
    user_id = session.get('email')
    registration = mongo.db.reception.find_one({'email': user_id})
    dname = session.get('fullname')
    details = list(mongo.db.donor.find({'dname':dname}))

    return render_template('dashboard1.html', registration=registration, details=details)

@app.route('/donate23', methods=['GET', 'POST'])
@logged_in
def donate():
    if request.method == 'POST':
        # Get Form Fields
        dname = request.form["dname"]
        sex = request.form["sex"]
        age = request.form["age"]
        weight = request.form["weight"]
        address = request.form["address"]
        disease = request.form["disease"]
        demail = request.form["demail"]

        # Insert data into MongoDB
        mongo.db.donors.insert_one({
            'DNAME': dname,
            'SEX': sex,
            'AGE': age,
            'WEIGHT': weight,
            'ADDRESS': address,
            'DISEASE': disease,
            'DEMAIL': demail
        })

        flash('Success! Donor details Added.', 'success')
        return redirect(url_for('donorlogs'))

    return render_template('donate.html')


@app.route('/donorlogs')
@logged_in
def donorlogs():
    # Access the 'donors' collection in MongoDB
    donor_collection = mongo.db.donors  # Assuming 'donors' is the collection name

    # Count the number of documents in the cursor
    num_logs = donor_collection.count_documents({})

    if num_logs > 0:
        logs = donor_collection.find()  # Retrieve all donor records
        return render_template('donorlogs.html', logs=logs)
    else:
        msg = 'No logs found'
        return render_template('donorlogs.html', msg=msg)
@app.route('/donorlogs1')

def donorlogs1():
    # Access the 'donors' collection in MongoDB
    donor_collection = mongo.db.donors  # Assuming 'donors' is the collection name

    # Count the number of documents in the cursor
    num_logs = donor_collection.count_documents({})

    if num_logs > 0:
        logs = donor_collection.find()  # Retrieve all donor records
        return render_template('donorlogs.html', logs=logs)
    else:
        msg = 'No logs found'
        return render_template('donorlogs.html', msg=msg)

# Blood Form
@app.route('/bloodform', methods=['GET', 'POST'])
@logged_in
def bloodform():
    if request.method == 'POST':
        # Get Form Fields
        d_id = request.form["d_id"]
        blood_group = request.form["blood_group"]
        packets = int(request.form["packets"])  # Ensure 'packets' is an integer

        # Insert data into MongoDB
        blood_collection = mongo.db.blood  # Assuming 'blood' is the collection name
        blood_collection.insert_one({
            'D_ID': d_id,
            'B_GROUP': blood_group,
            'PACKETS': packets
        })

        # Update the Blood Bank in MongoDB
        blood_bank_collection = mongo.db.bloodbank  # Assuming 'bloodbank' is the collection name
        blood_bank_collection.update_one(
            {'B_GROUP': blood_group},
            {'$inc': {'TOTAL_PACKETS': packets}},
            upsert=True  # Create the document if it doesn't exist
        )

        flash('Success! Donor Blood details Added.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('bloodform.html')

@app.route('/notifications')

def notifications():
    fname = None 
    bgroup = None 
    packet = None
    address = None
    if request.method == 'POST':
        fname = request.form.get['fname']
        bgroup = request.form.get['bgroup']
        packet = request.form.get['bpackets']
        address = request.form.get['address']
        notification = mongo.db.contact.find({'fname': fname, 'bgroup': bgroup,'bpackets':packet,'address':address})
        return redirect(url_for('notifications'))
    else:
    # Find notifications based on name and blood group
     notifications = list(mongo.db.contact.find({'fname': fname, 'bgroup': bgroup,'address':address}))

     notification_data = []
    for notification in notifications:
         data = {
            'fname': notification['F_NAME'],
            'bgroup': notification['B_GROUP'],
            'bpackets': notification['C_PACKETS'],
            'address':notification['ADRESS']
        }
         notification_data.append(data)

    return render_template('notification.html', notifications=notification_data)
@app.route('/notifications/accept')

def accept():
    # Retrieve notifications before processing
    notifications = mongo.db.blood_request.find()

    for notification in notifications:
        packet_str = notification.get('N_PACKETS', '0')

        # Check if packet_str is a non-empty string
        if packet_str:
            packet = int(packet_str)

            group = notification.get('NB_GROUP', '')

            # Update the Blood Bank collection
            mongo.db.blood.update_many({'B_GROUP': group}, {'$inc': {'TOTAL_PACKETS': -packet}})

            # Insert the result back into the notifications collection
            result = 'ACCEPTED'
            mongo.db.notifications.insert_one({'RESULT': result})

    # Update notifications after processing
    updated_notifications = mongo.db.blood_request.find()

    flash('Request Accepted', 'success')
    return redirect(url_for('notifications', notifications=updated_notifications))

@app.route('/notifications/decline')

def decline():
    msg = 'Request Declined'
    flash(msg, 'danger')

    # Get the current notification
    current_notification = mongo.db.contact.find_one()

    # Delete the notification based on its _id
    mongo.db.contact.delete_one({'_id': current_notification['_id']})

    return redirect(url_for('notifications'))
@app.route('/dashboard1/decline1')

def decline1():
    msg = 'Request Declined'
    flash(msg, 'danger')

    # Get the current notification
    current_donor = mongo.db.donor.find_one()

    # Delete the notification based on its _id
    mongo.db.donor.delete_one({'_id': current_donor['_id']})

    return redirect(url_for('dashboard1'))  
if __name__ == '__main__':
    app.debug = True
    app.run()

