import sqlite3
import os
import csv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json

# --- GLOBAL CONFIGURATION AND SECURITY INITIALIZATION ---

# Defaults in case constants.csv is missing or corrupt
CONSTANTS = {
    'SYSTEM_TITLE': 'Default Hospital System',
    'MASTER_KEY': 'a-default-key-that-should-be-replaced-by-a-file-value'
}

DB_NAME = 'patients.db'
AUTH_DB_NAME = 'users.db'
ENCRYPTION_KEY = None
FERNET_CRYPTO = None

# --- DATABASE SETUP ---

def setup_patient_db():
    """Creates the patient records table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS records (
            record_id INTEGER PRIMARY KEY,
            created_by TEXT NOT NULL,
            patient_name TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            date TEXT NOT NULL,
            doctor TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def setup_auth_db():
    """Creates the users table and inserts default accounts."""
    conn = sqlite3.connect(AUTH_DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL 
        )
    ''')
    
    # Insert default users (Admin, Doctor, Employee) if they don't exist
    users = [
        ('admin1', 'securepass', 'Admin'),
        ('doc22', 'docpass', 'Doctor'),
        ('emp33', 'emppass', 'Employee')
    ]
    
    for user_id, password, role in users:
        try:
            c.execute("INSERT INTO users (user_id, password, role) VALUES (?, ?, ?)", 
                      (user_id, password, role))
        except sqlite3.IntegrityError:
            # User already exists, ignore
            pass

    conn.commit()
    conn.close()

# --- INITIALIZATION FUNCTIONS ---

def load_constants():
    """Loads SYSTEM_TITLE and MASTER_KEY from constants.csv."""
    global CONSTANTS
    try:
        with open('constants.csv', mode='r', newline='') as file:
            reader = csv.reader(file)
            # Skip header
            next(reader, None)
            for key, value in reader:
                CONSTANTS[key.strip()] = value.strip()
        print(f"[INFO] Constants loaded successfully.")
    except FileNotFoundError:
        print("[WARNING] Could not load constants from constants.csv (File not found). Using defaults.")
    except Exception as e:
        print(f"[WARNING] Could not load constants from constants.csv (CSV library error] {e}). Using defaults.")

def initialize_security_and_db():
    """Initializes encryption key, Fernet, and databases."""
    global ENCRYPTION_KEY, FERNET_CRYPTO
    
    # 1. Load Constants
    load_constants()

    # 2. Derive Encryption Key from Master Key
    master_key = CONSTANTS.get('MASTER_KEY').encode()
    
    # Use PBKDF2 to derive a strong 32-byte key from the master_key (password)
    salt = b'a_fixed_salt_for_consistency'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    # Fernet requires a base64 URL-safe key
    key_32_bytes = kdf.derive(master_key)
    ENCRYPTION_KEY = base64.urlsafe_b64encode(key_32_bytes)
    
    # 3. Initialize Fernet
    try:
        FERNET_CRYPTO = Fernet(ENCRYPTION_KEY)
        print("[INFO] Encryption key derived from MASTER_KEY constant.")
    except Exception as e:
        print(f"[ERROR] Failed to initialize Fernet encryption: {e}")
        # Use a dummy key if initialization fails to prevent crash, but data will be garbage
        FERNET_CRYPTO = Fernet(Fernet.generate_key()) 

    # 4. Initialize Databases (Now the functions are defined above!)
    setup_patient_db()
    setup_auth_db()
    
    # 5. Final Success Message
    print(f"SUCCESS: Security systems initialized. System Title: {CONSTANTS['SYSTEM_TITLE']}")


def get_hospital_title():
    """Public function to retrieve the system title."""
    return CONSTANTS['SYSTEM_TITLE']

# --- SECURITY AND DATA FUNCTIONS ---

def authenticate_user(user_id, password):
    """Checks user credentials against the authentication database."""
    conn = sqlite3.connect(AUTH_DB_NAME)
    c = conn.cursor()
    
    # Basic input sanitation (prevents common SQL injection)
    if any(char in user_id for char in ['--', "'", '"', ';']):
        print("SQLI ATTACK BLOCKED: Invalid characters in user_id.")
        return None

    c.execute("SELECT role FROM users WHERE user_id = ? AND password = ?", (user_id, password))
    result = c.fetchone()
    conn.close()
    
    if result:
        return result[0] # Returns the role (e.g., 'Admin', 'Doctor')
    return None

def encrypt_record(data):
    """Encrypts a dictionary of record data using Fernet."""
    try:
        # Convert dictionary to JSON string, encode to bytes, then encrypt
        json_data = json.dumps(data)
        return FERNET_CRYPTO.encrypt(json_data.encode())
    except Exception as e:
        print(f"[ENCRYPTION ERROR] Failed to encrypt data: {e}")
        return None

def decrypt_record(encrypted_data):
    """Decrypts a bytes object into a dictionary of record data."""
    try:
        # Decrypt, decode bytes, then load the JSON string into a dictionary
        decrypted_bytes = FERNET_CRYPTO.decrypt(encrypted_data)
        json_data = decrypted_bytes.decode()
        return json.loads(json_data)
    except Exception as e:
        print(f"[DECRYPTION ERROR] Failed to decrypt data. Key mismatch or data corruption: {e}")
        return None

def sanitize_input(data):
    """Simple sanitation check for potentially malicious input."""
    if isinstance(data, str) and any(char in data for char in ['--', "'", '"', ';']):
        return "SQLI ATTACK BLOCKED"
    return data

# --- CRUD FUNCTIONS ---

def add_record(user_id, patient_name, diagnosis, condition, date, doctor):
    """Adds a new patient record to the database."""
    
    # Sanitize inputs before using them in SQL or data structure
    patient_name = sanitize_input(patient_name)
    diagnosis = sanitize_input(diagnosis)
    condition = sanitize_input(condition)
    date = sanitize_input(date)
    doctor = sanitize_input(doctor)
    
    if patient_name == "SQLI ATTACK BLOCKED":
        return None

    # Data to be encrypted
    sensitive_data = {
        "Diagnosis": diagnosis,
        "Health_Condition": condition,
    }
    
    encrypted_data = encrypt_record(sensitive_data)
    if not encrypted_data:
        return None # Encryption failed

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO records (created_by, patient_name, encrypted_data, date, doctor) 
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, patient_name, encrypted_data, date, doctor))
        record_id = c.lastrowid
        conn.commit()
        return record_id
    except Exception as e:
        print(f"[DATABASE ERROR] Failed to add record: {e}")
        return None
    finally:
        conn.close()

def get_record(user_id, record_id):
    """Retrieves and decrypts a specific record."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Sanitize input
    record_id = sanitize_input(record_id)
    if record_id == "SQLI ATTACK BLOCKED":
        return record_id
        
    try:
        c.execute("SELECT encrypted_data, patient_name, date, doctor FROM records WHERE record_id = ?", (record_id,))
        result = c.fetchone()
        conn.close()
        
        if result:
            encrypted_data, patient_name, date, doctor = result
            
            # Decrypt sensitive data
            decrypted_data = decrypt_record(encrypted_data)
            
            if decrypted_data is None:
                return None # Decryption failed
            
            # Combine non-sensitive and sensitive data
            full_record = {
                'Patient_Name': patient_name,
                'Date': date,
                'Doctor': doctor,
            }
            full_record.update(decrypted_data)
            return full_record
            
    except Exception as e:
        print(f"[DATABASE ERROR] Failed to retrieve record: {e}")
        return None
    finally:
        conn.close()


def list_all_records():
    """Lists all records with non-sensitive fields for the dashboard view."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT record_id, patient_name, date, doctor FROM records ORDER BY record_id DESC")
    results = c.fetchall()
    conn.close()
    
    records = []
    for row in results:
        records.append({
            'record_id': row[0],
            'patient_name': row[1],
            'date': row[2],
            'doctor': row[3]
        })
    return records

# --- RUN INITIALIZATION ---
# This must be the last thing in the file to ensure all functions are defined first.
initialize_security_and_db()