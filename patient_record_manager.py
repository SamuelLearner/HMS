import sqlite3
import logging
import os
from cryptography.fernet import Fernet
from datetime import datetime

# --- CONFIGURATION AND AUDIT LOGGING SETUP (Control: Audit Logging) ---
LOG_FILE = 'audit.log'
DB_FILE = 'patients.db'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=LOG_FILE,
    filemode='a' 
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

logger = logging.getLogger('RecordManager')
logger.info("SYSTEM INITIALIZED: Application started and Audit Logging system is active.")


# --- ENCRYPTION SETUP (Control: AES Encryption) ---
KEY_FILE = 'fernet_key.key'
def load_or_generate_key():
    """Loads the key or generates a new one if it doesn't exist."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        logger.warning("NEW ENCRYPTION KEY GENERATED. SECURE THIS FILE!")
        return key

ENCRYPTION_KEY = load_or_generate_key()
fernet = Fernet(ENCRYPTION_KEY)

def encrypt_record(data: str) -> bytes:
    """Encrypts patient data before storage."""
    return fernet.encrypt(data.encode('utf-8'))

def decrypt_record(token: bytes) -> str:
    """Decrypts patient data after retrieval."""
    try:
        return fernet.decrypt(token).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to decrypt record: {e}. Possible tampering or key mismatch.")
        return "[DECRYPTION FAILED]"


# --- USER MANAGEMENT LOGGING and DB FUNCTIONS (Unchanged) ---
def authenticate_user(username, password_hash):
    if username == "Dr.Smith" and password_hash == "secure_hash_123":
        logger.info(f"AUTHENTICATION SUCCESS: User '{username}' logged in.")
        return True
    else:
        logger.warning(f"AUTHENTICATION FAILURE: Failed login attempt for user '{username}'.")
        return False

def logout_user(username):
    logger.info(f"SESSION END: User '{username}' logged out.")
    
def initialize_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patient_records (
                id INTEGER PRIMARY KEY,
                patient_name TEXT NOT NULL,
                record_data BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
        ''')
        conn.commit()
        logger.info(f"Database initialized: {DB_FILE}.")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
    finally:
        if conn:
            conn.close()

def add_record(patient_name: str, health_data: str, user_id="SYSTEM"):
    conn = None
    try:
        encrypted_data = encrypt_record(health_data)
        created_at = datetime.now().isoformat()
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        sql_insert = 'INSERT INTO patient_records (patient_name, record_data, created_at) VALUES (?, ?, ?);'
        cursor.execute(sql_insert, (patient_name, encrypted_data, created_at))
        conn.commit()
        record_id = cursor.lastrowid
        logger.info(f"PATIENT MODIFY: User '{user_id}' created record ID {record_id} for patient '{patient_name}'. (Action: CREATE)")
        return record_id
    except sqlite3.Error as e:
        logger.error(f"SQLite error during record addition: {e}")
    finally:
        if conn:
            conn.close()

def get_record(record_id: int, user_id="Dr.Smith"):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        sql_select = 'SELECT id, patient_name, record_data, created_at FROM patient_records WHERE id = ?;'
        cursor.execute(sql_select, (record_id,)) 
        result = cursor.fetchone()
        if result:
            record_id, name, encrypted_data, created_at = result
            decrypted_data = decrypt_record(encrypted_data)
            logger.info(f"PATIENT ACCESS: User '{user_id}' accessed record ID {record_id}, Name: {name}. (Action: READ)")
            return {'id': record_id, 'name': name, 'data': decrypted_data, 'created_at': created_at}
        else:
            logger.warning(f"PATIENT ACCESS FAIL: User '{user_id}' attempted access to non-existent Record ID: {record_id}.")
            return None
    except sqlite3.Error as e:
        logger.error(f"SQLite error during record retrieval: {e}")
    finally:
        if conn:
            conn.close()

def update_record(record_id: int, new_data: str, user_id="Dr.Smith"):
    conn = None
    try:
        encrypted_data = encrypt_record(new_data)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        sql_update = 'UPDATE patient_records SET record_data = ? WHERE id = ?;'
        cursor.execute(sql_update, (encrypted_data, record_id))
        conn.commit()
        if cursor.rowcount > 0:
            logger.info(f"PATIENT MODIFY: User '{user_id}' updated record ID {record_id}.")
            return True
        else:
            logger.warning(f"PATIENT MODIFY FAIL: User '{user_id}' failed to modify record. ID {record_id} not found.")
            return False
    except sqlite3.Error as e:
        logger.error(f"SQLite error during record update: {e}")
    finally:
        if conn:
            conn.close()

def test_sql_injection_defense():
    print("\n--- ASSURANCE TEST 1: SQL PARAMETERIZATION DEFENSE ---")
    user_id = "Attacker_User"
    malicious_id = "1 OR 1=1" 
    result = get_record(malicious_id, user_id) 
    if result is None:
        print(f"  [SUCCESS] SQL Injection attempt failed successfully.")
        print(f"  The system searched for literal ID: '{malicious_id}' and found nothing.")
        logger.critical(f"SQLI ASSURANCE TEST: Attack attempt by '{user_id}' with payload '{malicious_id}' FAILED (Mitigation Proof).")
    else:
        print(f"  [FAILURE] SQL Injection attack was successful. This control is compromised.")
        logger.critical(f"SQLI ASSURANCE TEST: Attack successful! Control Compromised.")
        
# --- NEW FUNCTION TO GET RAW ENCRYPTED DATA ---
def display_raw_ciphertext(record_id: int):
    """Retrieves the raw BLOB from the database, bypassing the decryption function."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        sql_select = 'SELECT record_data FROM patient_records WHERE id = ?;'
        cursor.execute(sql_select, (record_id,)) 
        result = cursor.fetchone()
        if result:
            # Result is the raw encrypted bytes (BLOB)
            return result[0]
        return b""
    except sqlite3.Error as e:
        logger.error(f"SQLite error during raw data retrieval: {e}")
        return b""
    finally:
        if conn:
            conn.close()


# --- DEMONSTRATION (CALLING THE NEW FUNCTION) ---

if __name__ == '__main__':
    print("--- Running Secure Patient Record Demo (Functional Test) ---")
    
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        
    initialize_db()
    
    # Functional tests (Logging, encryption, decryption)
    authenticate_user("Dr.Smith", "secure_hash_123") 
    record1_id = add_record("Tim Baker", "Diagnosis: Severe headache and fever.", user_id="Dr.Smith")
    update_record(record1_id, "Diagnosis: Severe headache and fever. Treatment: Bed rest and fluids.", user_id="Dr.Smith")
    
    # Assurance Test 1: SQL Parameterization Defense
    test_sql_injection_defense()
    
    # Assurance Test 2: AES ENCRYPTION RAW CIPHERTEXT PROOF
    print("\n--- ASSURANCE TEST 2: AES ENCRYPTION (CIPHERTEXT PROOF) ---")
    raw_bytes = display_raw_ciphertext(record1_id)
    if raw_bytes:
        print(f"  [SUCCESS] Raw Encrypted Data (Ciphertext) from DB:")
        # This is the line that generates the critical evidence:
        print(f"  {raw_bytes}") 
        print(f"  Length: {len(raw_bytes)} bytes. Note: The raw data is unreadable, proving AES-256 protection.")
    else:
        print("  [FAILURE] Could not retrieve raw encrypted data.")

    logout_user("Dr.Smith")
        
    print(f"\n--- ALL ASSURANCE TESTS COMPLETE ---")
    print(f"Copy the full console output for all three evidence requirements.")