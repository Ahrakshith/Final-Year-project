from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime
import os
import requests
from flask_socketio import SocketIO, send
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
import pydub
from pydub import AudioSegment
import speech_recognition as sr
from googletrans import Translator, LANGUAGES

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Initialize SocketIO with eventlet
socketio = SocketIO(app, async_mode='eventlet')  # Use 'eventlet' as the async mode

# MongoDB configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['medical_system']

# Collections
patients_collection = db['patients']
users_collection = db['users']
audit_logs_collection = db['audit_logs']

# RxNorm API configuration
RXNORM_API_URL = 'https://rxnav.nlm.nih.gov/REST/rxcui.json'

# OpenFDA API configuration
OPENFDA_API_URL = 'https://api.fda.gov/drug/label.json'

# Configuration for audio uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp3', 'wav', 'ogg', 'flac', 'aac', 'wma', 'm4a'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

translator = Translator()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

    # Fetch the patient's data from the database
    patient_data = patients_collection.find_one({'user_id': session['user_id']})

    # Fetch all previous prescriptions for the patient
    if patient_data:
        prescriptions = list(audit_logs_collection.find({'patient_id': str(patient_data['_id'])}))
    else:
        prescriptions = []  # No patient data exists yet

    if request.method == 'POST':
        age = request.form.get('age')
        audio_file = request.files.get('file')
        language = request.form.get('language', 'en')  # Default to English if not provided

        # Check if a file was uploaded
        if not audio_file or audio_file.filename == '':
            flash('No file selected for upload.', 'error')
            return redirect(url_for('patient_side'))

        # Save audio file
        audio_file_path = os.path.join('audio_files', secure_filename(audio_file.filename))
        audio_file.save(audio_file_path)

        # Convert audio to text using speech recognition
        try:
            recognizer = sr.Recognizer()
            with sr.AudioFile(audio_file_path) as source:
                audio = recognizer.record(source)
                transcription = recognizer.recognize_google(audio, language=language)

            # Translate to English if the audio is in Kannada
            if language == 'kn':
                translation = translator.translate(transcription, src='kn', dest='en')
                translated_text = translation.text
            else:
                translated_text = transcription  # No translation needed for English

        except Exception as e:
            transcription = f"Error in speech-to-text conversion: {e}"
            translated_text = "Translation not available."

        # Save patient data
        if patient_data:
            # Update existing patient data
            patients_collection.update_one(
                {'_id': patient_data['_id']},
                {'$set': {
                    'age': age,
                    'transcription': transcription,
                    'translated_text': translated_text,  # Save translated text
                    'updated_at': datetime.now()
                }}
            )
        else:
            # Create new patient data
            patient_id = patients_collection.insert_one({
                'name': session['username'],  # Use the username as the patient's name
                'age': age,
                'transcription': transcription,
                'translated_text': translated_text,  # Save translated text
                'diagnosis': '',
                'prescription': '',
                'created_at': datetime.now(),
                'updated_at': datetime.now(),
                'user_id': session['user_id']  # Link the patient to the logged-in user
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
        return redirect(url_for('patient_side'))

    return render_template('patient.html', patient_data=patient_data, prescriptions=prescriptions)
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

        # Update patient data
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

@app.route('/update_patient/<patient_id>', methods=['GET', 'POST'])
def update_patient(patient_id):
    if 'user_id' not in session or session['role'] != 'doctor':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('login'))

    patient = patients_collection.find_one({'_id': patient_id})

    if request.method == 'POST':
        diagnosis = request.form.get('diagnosis')
        medicines = []
        durations = []

        # Collect all medicines and durations
        i = 1
        while f"medicine{i}" in request.form:
            medicine = request.form.get(f"medicine{i}")
            duration = request.form.get(f"duration{i}")
            medicines.append(medicine)
            durations.append(duration)
            i += 1

        # Combine medicines and durations into a single prescription string
        prescription = ", ".join([f"{medicines[j]} ({durations[j]})" for j in range(len(medicines))])

        # Update patient data
        patients_collection.update_one(
            {'_id': patient_id},
            {'$set': {
                'diagnosis': diagnosis,
                'prescription': prescription,
                'updated_at': datetime.now()
            }}
        )

        # Log the action
        details = f"Diagnosis: {diagnosis}, Prescription: {prescription}"
        audit_logs_collection.insert_one({
            'user_id': session['user_id'],
            'patient_id': patient_id,
            'action': 'update',
            'details': details,
            'timestamp': datetime.now()
        })

        flash('Diagnosis and prescription updated.', 'success')
        return redirect(url_for('doctor_side'))

    return render_template('update_patient.html', patient=patient)

# ==================== Prescription Validation ====================

def validate_prescription(diagnosis, prescription):
    """
    Validate if a prescription is appropriate for a given diagnosis.
    First checks the Indian medicines collection, then falls back to global APIs.
    """
    try:
        # Step 1: Clean the prescription name (e.g., "Crocin 500mg" -> "Crocin")
        prescription_clean = prescription.split(' ')[0]

        # Step 2: Check if the medicine is in the Indian medicines collection
        medicine = db.indian_medicines.find_one({
            '$or': [
                {'brand_name': prescription_clean},
                {'generic_name': prescription_clean}
            ]
        })

        if medicine:
            # Step 3: Check if the diagnosis is in the medicine's indications
            if diagnosis.lower() in [indication.lower() for indication in medicine.get('indications', [])]:
                return True, f"Prescription '{prescription}' is valid for '{diagnosis}' (Indian Medicine)."
            else:
                return False, f"Prescription '{prescription}' is not valid for '{diagnosis}' (Indian Medicine)."

        # Step 4: If not found in Indian medicines, use global APIs
        rxcui = get_rxcui(prescription_clean)
        if not rxcui:
            return False, f"Prescription '{prescription}' not found in RxNorm."

        # Step 5: Use OpenFDA to validate the prescription
        response = requests.get(
            OPENFDA_API_URL,
            params={'search': f'openfda.brand_name:"{prescription_clean}"'}
        )

        if response.status_code != 200:
            return False, f"Failed to validate prescription. OpenFDA API returned status code {response.status_code}."

        data = response.json()
        if not data.get('results'):
            return False, f"Prescription '{prescription}' not found in OpenFDA."

        # Step 6: Check if the diagnosis is in the medication's indications
        for result in data['results']:
            if 'indications_and_usage' in result:
                if diagnosis.lower() in result['indications_and_usage'][0].lower():
                    return True, f"Prescription '{prescription}' is valid for '{diagnosis}' (Global Medicine)."

        return False, f"Prescription '{prescription}' is not valid for '{diagnosis}' (Global Medicine)."

    except Exception as e:
        # Handle any unexpected errors
        return False, f"An error occurred while validating the prescription: {str(e)}"

def get_rxcui(prescription):
    # RxNorm API endpoint
    url = f"{RXNORM_API_URL}?name={prescription}"

    # Make the API request
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if 'idGroup' in data and 'rxnormId' in data['idGroup']:
            return data['idGroup']['rxnormId'][0]
    return None

@app.route('/validate_prescription')
def validate_prescription_route():
    diagnosis = request.args.get('diagnosis')
    prescription = request.args.get('prescription')

    is_valid, message = validate_prescription(diagnosis, prescription)
    return jsonify({'message': message})

# ==================== Main Entry Point ====================

if __name__ == '__main__':
    socketio.run(app, debug=True)