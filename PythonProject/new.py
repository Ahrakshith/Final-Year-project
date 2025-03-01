from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# MongoDB configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['medical_system']

# Collections
patients_collection = db['patients']
users_collection = db['users']
audit_logs_collection = db['audit_logs']

# ==================== User Authentication ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'patient')  # Default to 'patient' if not provided
        hashed_password = generate_password_hash(password)

        # Check if username already exists
        if users_collection.find_one({'username': username}):
            flash('Username already exists. Please choose another.', 'error')
        else:
            # Insert new user into the database
            users_collection.insert_one({
                'username': username,
                'password_hash': hashed_password,
                'role': role
            })
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find the user in the database
        user = users_collection.find_one({'username': username})

        # Check if the user exists and the password is correct
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Logged in successfully!', 'success')

            # Redirect based on role
            if user['role'] == 'patient':
                return redirect(url_for('patient_side'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_side'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin_side'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ==================== Patient Interface ====================

@app.route('/patient', methods=['GET', 'POST'])
def patient_side():
    if 'user_id' not in session or session['role'] != 'patient':
        flash('Please log in as a patient to access this page.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        age = request.form.get('age')
        sex = request.form.get('sex')
        audio_file = request.files.get('file')

        # Save audio file (for demonstration, we skip processing)
        audio_file_path = os.path.join('audio_files', audio_file.filename)
        audio_file.save(audio_file_path)

        # Simulate transcription and translation
        transcription = "Sample transcription"
        language = "en"

        # Save patient data
        patient_id = patients_collection.insert_one({
            'name': name,
            'age': age,
            'sex': sex,
            'language': language,
            'transcription': transcription,
            'diagnosis': '',
            'prescription': '',
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }).inserted_id

        # Log the action
        audit_logs_collection.insert_one({
            'user_id': session['user_id'],
            'patient_id': str(patient_id),
            'action': 'create',
            'details': 'New patient record created',
            'timestamp': datetime.now()
        })

        flash('Patient data added successfully!', 'success')
        return render_template('patient.html', transcribed_text=transcription)
    return render_template('patient.html')

# ==================== Doctor Interface ====================

@app.route('/doctor', methods=['GET', 'POST'])
def doctor_side():
    if 'user_id' not in session or session['role'] != 'doctor':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        diagnosis = request.form.get('diagnosis')
        prescription = request.form.get('prescription')

        patients_collection.update_one(
            {'_id': patient_id},
            {'$set': {
                'diagnosis': diagnosis,
                'prescription': prescription,
                'updated_at': datetime.now()
            }}
        )

        # Log the action
        audit_logs_collection.insert_one({
            'user_id': session['user_id'],
            'patient_id': patient_id,
            'action': 'update',
            'details': f'Diagnosis: {diagnosis}, Prescription: {prescription}',
            'timestamp': datetime.now()
        })

        flash('Diagnosis and prescription updated.', 'success')

    # Fetch all patients
    patients = list(patients_collection.find())
    return render_template('doctor.html', patients=patients)

# ==================== Admin Interface ====================

@app.route('/admin')
def admin_side():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('login'))

    patients = list(patients_collection.find())
    logs = list(audit_logs_collection.find())
    return render_template('admin.html', patients=patients, logs=logs)

# ==================== Main Entry Point ====================

if __name__ == '__main__':
    app.run(debug=True)