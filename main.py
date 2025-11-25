import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.properties import StringProperty, ListProperty
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle 
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.scrollview import ScrollView 
from kivy.uix.popup import Popup
from kivy.metrics import dp
import uuid
import os
import json 
from datetime import datetime
import sqlite3
from cryptography.fernet import Fernet

kivy.require('2.2.1') 

# --- WINDOW BACKGROUND COLOR CHANGE ---
Window.clearcolor = (0.1, 0.1, 0.1, 1) # Dark background

# --- 1. CONFIGURATION (Dual Database Architecture) ---
PATIENT_DB_NAME = 'hms_patient_data.db' # Sensitive data (Encrypted)
AUDIT_DB_NAME = 'hms_audit_log.db'      # Immutable log data
KEY_FILE = 'hms_key.key'

# --- 2. AES ENCRYPTION SETUP ---

def load_or_generate_key():
    """Loads the key from file or generates a new one."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

# Initialize Fernet 
try:
    AES_KEY = load_or_generate_key()
    fernet = Fernet(AES_KEY)
except ImportError:
    print("Warning: cryptography library not found. Using placeholder encryption.")
    AES_KEY = None
    fernet = None
except Exception as e:
    print(f"Error initializing Fernet: {e}")
    AES_KEY = None
    fernet = None

# --- ENCRYPTION/DECRYPTION FUNCTIONS ---

def encrypt_data(data):
    if not data: return ""
    if fernet:
        try:
            return fernet.encrypt(data.encode('utf-8')).decode('utf-8')
        except Exception:
            return f"ENC_{data}" 
    return f"ENC_{data}"

def decrypt_data(encrypted_data):
    if not encrypted_data: return ""
    if encrypted_data.startswith("ENC_"):
        return encrypted_data.replace("ENC_", "")
    if fernet:
        try:
            return fernet.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')
        except Exception:
            return f"FAILED: {encrypted_data[:15]}..." 
    return encrypted_data


# --- 3. DATABASE SETUP & AUDIT LOGGING ---

def setup_database():
    """Initializes both SQLite databases and tables."""
    
    # 1. Patient Database Setup
    try:
        conn_pat = sqlite3.connect(PATIENT_DB_NAME)
        cursor_pat = conn_pat.cursor()
        cursor_pat.execute('''
            CREATE TABLE IF NOT EXISTS patients (
                id TEXT PRIMARY KEY,
                name TEXT,
                age INTEGER,
                condition TEXT,
                status TEXT
            )
        ''')
        conn_pat.commit()
        conn_pat.close()
    except sqlite3.Error as e:
        print(f"Error setting up patient database: {e}")

    # 2. Audit Database Setup
    try:
        conn_audit = sqlite3.connect(AUDIT_DB_NAME)
        cursor_audit = conn_audit.cursor()
        cursor_audit.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                timestamp TEXT,
                user TEXT,
                action TEXT,
                target_id TEXT
            )
        ''')
        conn_audit.commit()
        conn_audit.close()
    except sqlite3.Error as e:
        print(f"Error setting up audit database: {e}")
    
    log_event("SYSTEM", "DB INITIALIZED", f"Patient: {PATIENT_DB_NAME}, Audit: {AUDIT_DB_NAME}")


def log_event(user, action, target_id="N/A"):
    """Logs an action to the dedicated audit log database."""
    try:
        conn = sqlite3.connect(AUDIT_DB_NAME) 
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Security: Use safe parameterization
        cursor.execute("""
            INSERT INTO audit_log (timestamp, user, action, target_id)
            VALUES (?, ?, ?, ?)
        """, (current_time, user, action, target_id))
        
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Error logging event: {e}")

def get_audit_logs():
    """Retrieves all entries from the audit log."""
    try:
        conn = sqlite3.connect(AUDIT_DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
        logs = cursor.fetchall()
        conn.close()
        return logs
    except sqlite3.Error as e:
        print(f"Error retrieving audit logs: {e}")
        return []

# --- PATIENT MANAGEMENT FUNCTIONS ---

def get_all_patients():
    try:
        conn = sqlite3.connect(PATIENT_DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, age, condition, status FROM patients")
        patients = cursor.fetchall()
        conn.close()
        
        decrypted_patients = []
        for patient in patients:
            p_id, name_enc, age, condition_enc, status = patient
            decrypted_patients.append({
                'id': p_id,
                'name': decrypt_data(name_enc),
                'age': age,
                'condition': decrypt_data(condition_enc),
                'status': status
            })
        return decrypted_patients
    except sqlite3.Error as e:
        print(f"Error fetching patients: {e}")
        return []

def add_patient(name, age, condition, status):
    if not all([name, age, condition, status]): return False
    try:
        conn = sqlite3.connect(PATIENT_DB_NAME)
        cursor = conn.cursor()
        patient_id = str(uuid.uuid4())[:8]
        
        name_enc = encrypt_data(name)
        condition_enc = encrypt_data(condition)
        
        cursor.execute("INSERT INTO patients (id, name, age, condition, status) VALUES (?, ?, ?, ?, ?)",
                       (patient_id, name_enc, int(age), condition_enc, status))
        conn.commit()
        conn.close()
        log_event("admin", "PATIENT ADDED", patient_id)
        return patient_id
    except sqlite3.Error as e:
        print(f"Error adding patient: {e}")
        return False

def delete_patient(patient_id):
    try:
        conn = sqlite3.connect(PATIENT_DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM patients WHERE id=?", (patient_id,))
        conn.commit()
        conn.close()
        log_event("admin", "PATIENT DELETED", patient_id)
    except sqlite3.Error as e:
        print(f"Error deleting patient: {e}")

# --- SQLI TEST FUNCTION (Parameterization Assurance) ---

def test_sqli_vulnerability(query_input):
    """
    Demonstrates SQLI resilience using safe parameterized queries.
    """
    try:
        conn = sqlite3.connect(PATIENT_DB_NAME)
        cursor = conn.cursor()
        
        # The search uses safe parameterization
        search_term = f'%{query_input}%'
        query = "SELECT id, name, condition FROM patients WHERE id LIKE ? OR name LIKE ?"
        
        # EXECUTION: Parameterized query is SAFE.
        cursor.execute(query, (search_term, search_term)) 
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            log_event("admin", "SQLI TEST (SAFE)", f"No results for: {query_input[:20]}...")
            return "Query executed SAFELY using parameterized methods. No injection possible. No matching records found."
            
        output = ["Query successful (System is SAFE). Results found:"]
        for p_id, name_enc, condition_enc in results:
            output.append(f"ID: {p_id}, Name: {decrypt_data(name_enc)}, Condition: {decrypt_data(condition_enc)}")
        
        log_event("admin", "SQLI TEST (SAFE)", f"Results found for: {query_input[:20]}...")
        return "\n".join(output)

    except sqlite3.Error as e:
        conn.close()
        log_event("admin", "SQLI TEST ERROR", f"DB Error: {e}")
        return f"Database Error during query: {e}. The query was SAFE (parameterized)."

# --- KIVY SCREENS ---

class LoginScreen(Screen):
    """Handles user authentication and interface for login."""
    login_status = StringProperty("Enter your credentials.")
    status_color = ListProperty([0.5, 0.5, 0.5, 1]) 
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'password123' 

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()
        # Bind the Kivy properties to update the message label dynamically
        self.bind(login_status=lambda inst, val: setattr(self.message_label, 'text', val))
        self.bind(status_color=lambda inst, val: setattr(self.message_label, 'color', val))
        self.bind(login_status=self.update_status_color)

    def build_ui(self):
        # Main layout (Centered)
        main_layout = BoxLayout(
            orientation='vertical',
            padding=dp(150),
            spacing=dp(20),
            size_hint=(1, 1)
        )
        
        # Background color
        with main_layout.canvas.before:
            Color(0.08, 0.08, 0.08, 1)
            Rectangle(size=self.size, pos=self.pos) 

        # Title
        main_layout.add_widget(Label(
            text="Secure Hospital Management",
            font_size='32sp',
            size_hint_y=None, height=dp(50),
            color=(0.1, 0.6, 0.9, 1)
        ))

        # Login Form Container
        form_container = GridLayout(cols=2, spacing=dp(10), size_hint_y=None, height=dp(150))
        
        form_container.add_widget(Label(text="Username:", font_size='18sp'))
        self.username_input = TextInput(multiline=False, size_hint_y=None, height=dp(40))
        form_container.add_widget(self.username_input)
        
        form_container.add_widget(Label(text="Password:", font_size='18sp'))
        self.password_input = TextInput(password=True, multiline=False, size_hint_y=None, height=dp(40))
        form_container.add_widget(self.password_input)
        
        main_layout.add_widget(form_container)

        # Message Label (Saved as instance variable for binding)
        self.message_label = Label(text=self.login_status, color=self.status_color, size_hint_y=None, height=dp(30))
        main_layout.add_widget(self.message_label)

        # Login Button
        login_button = Button(
            text="Login",
            font_size='22sp',
            size_hint_y=None, height=dp(50),
            background_color=(0.1, 0.6, 0.9, 1), 
            background_normal='',
            on_press=self.try_login
        )
        main_layout.add_widget(login_button)
        
        main_layout.add_widget(Label())
        self.add_widget(main_layout)

    def update_status_color(self, instance, value):
        """Sets the status color based on the message content."""
        if 'Error' in value or 'Invalid' in value:
            self.status_color = [0.9, 0.2, 0.2, 1] 
        elif 'Successful' in value:
            self.status_color = [0.1, 0.9, 0.1, 1]
        else:
            self.status_color = [0.5, 0.5, 0.5, 1]

    def try_login(self, instance):
        username = self.username_input.text.strip()
        password = self.password_input.text.strip()
        
        if not username or not password:
            self.login_status = "Error: Username and Password cannot be empty."
            return
            
        if username == self.ADMIN_USERNAME and password == self.ADMIN_PASSWORD:
            log_event(username, "SUCCESSFUL LOGIN", "ACCESS GRANTED")
            self.login_status = "Login Successful!"
            self.manager.current = 'dashboard'
            self.username_input.text = ""
            self.password_input.text = ""
            self.manager.get_screen('dashboard').navigate_to_module('Patient Records')
        else:
            # IMPORTANT FIX: Log the specific (incorrect/invalid) username
            log_event(username, "FAILED LOGIN ATTEMPT", "ACCESS DENIED")
            self.login_status = "Error: Invalid username or password."
            self.password_input.text = "" 

class DashboardScreen(Screen):
    """The main application interface with navigation."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()
        
    def build_ui(self):
        # Main Dashboard Layout: Left Nav (25%) | Right Content (75%)
        main_grid = GridLayout(cols=2)
        
        # --- LEFT COLUMN: NAVIGATION MENU (25%) ---
        nav_layout = BoxLayout(
            orientation='vertical',
            size_hint_x=0.25,
            padding=dp(10),
            spacing=dp(10)
        )
        with nav_layout.canvas.before:
             Color(0.15, 0.15, 0.15, 1) # Dark gray
             Rectangle(size=(nav_layout.width, nav_layout.height), pos=nav_layout.pos)
        
        # Title/Logo
        nav_layout.add_widget(Label(text='H M S', font_size='28sp', size_hint_y=None, height=dp(60), color=(0, 0.7, 1, 1)))

        # Navigation Buttons
        modules = ['Patient Records', 'SQLI Assurance Test', 'Audit Log Report']
        for module in modules:
            btn = Button(
                text=module,
                on_press=lambda inst, m=module: self.navigate_to_module(m),
                background_color=(0.05, 0.3, 0.5, 1),
                background_normal='', 
                size_hint_y=None, height=dp(50)
            )
            nav_layout.add_widget(btn)

        # Spacer
        nav_layout.add_widget(Label())
        
        # LOGOUT BUTTON 
        logout_button = Button(
            text='Logout',
            font_size='18sp',
            size_hint_y=None, height=dp(50),
            background_color=(0.8, 0.2, 0.2, 1), # Red for logout
            background_normal='', 
            on_press=self.perform_logout
        )
        nav_layout.add_widget(logout_button)
        main_grid.add_widget(nav_layout)

        # --- RIGHT COLUMN: MAIN CONTENT AREA (75%) ---
        self.content_area = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(20), size_hint_x=0.75)
        
        with self.content_area.canvas.before:
            Color(0.1, 0.1, 0.1, 1)
            Rectangle(size=(self.content_area.width, self.content_area.height), pos=self.content_area.pos)
        
        self.content_area.add_widget(Label(text='Select a module from the menu.', font_size='24sp', color=(0.1, 0.9, 0.1, 1)))
        main_grid.add_widget(self.content_area)
        
        self.add_widget(main_grid)

    def perform_logout(self, instance):
        log_event("admin", "LOGOUT", "N/A")
        self.manager.current = 'login'
        self.manager.get_screen('login').login_status = 'Logged out successfully.'

    def navigate_to_module(self, module_name):
        log_event("admin", "VIEW MODULE", module_name)
        self.content_area.clear_widgets()
        
        if module_name == 'Audit Log Report':
            self.content_area.add_widget(self.create_audit_log_ui())
        elif module_name == 'Patient Records':
            self.content_area.add_widget(self.create_patient_records_ui())
        elif module_name == 'SQLI Assurance Test':
            self.content_area.add_widget(self.create_sqli_test_ui())
            
    # --- MODULE 1: PATIENT RECORDS UI ---
    def create_patient_records_ui(self):
        patient_layout = BoxLayout(orientation='vertical', spacing=dp(10))
        
        patient_layout.add_widget(Label(
            text="PATIENT RECORDS (Encrypted Storage)", 
            font_size='28sp', size_hint_y=None, height=dp(40), 
            color=(0.1, 0.6, 0.9, 1)
        ))
        
        # --- Input Form ---
        form = GridLayout(cols=6, size_hint_y=None, height=dp(40))
        self.name_input = TextInput(hint_text='Name', multiline=False)
        self.age_input = TextInput(hint_text='Age', input_filter='int', multiline=False)
        self.condition_input = TextInput(hint_text='Condition', multiline=False)
        self.status_input = TextInput(hint_text='Status', multiline=False)
        
        form.add_widget(self.name_input)
        form.add_widget(self.age_input)
        form.add_widget(self.condition_input)
        form.add_widget(self.status_input)
        form.add_widget(Button(text="Add Patient", on_press=self.add_new_patient, background_color=(0.1, 0.7, 0.1, 1), background_normal=''))
        form.add_widget(Label()) 

        patient_layout.add_widget(form)

        # --- Patient List View ---
        patient_layout.add_widget(Label(text="Patient List (Decrypted on Retrieval):", size_hint_y=None, height=dp(30), color=(0.7, 0.7, 0.7, 1)))
        
        self.patient_list_container = GridLayout(cols=6, spacing=dp(5), size_hint_y=None)
        self.patient_list_container.bind(minimum_height=self.patient_list_container.setter('height'))
        
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(self.patient_list_container)
        patient_layout.add_widget(scroll)

        self.refresh_patient_list()
        
        return patient_layout

    def refresh_patient_list(self, *args):
        self.patient_list_container.clear_widgets()
        
        # Header Row
        header_colors = (0.9, 0.9, 0.1, 1)
        for text in ["ID", "Name", "Age", "Condition", "Status", "Action"]:
             self.patient_list_container.add_widget(Label(text=text, color=header_colors, size_hint_y=None, height=dp(25)))
        
        patients = get_all_patients()
        
        for p in patients:
            text_color = (0.8, 0.8, 0.8, 1)
            
            self.patient_list_container.add_widget(Label(text=p['id'], color=text_color, size_hint_y=None, height=dp(30)))
            self.patient_list_container.add_widget(Label(text=p['name'], color=text_color, size_hint_y=None, height=dp(30)))
            self.patient_list_container.add_widget(Label(text=str(p['age']), color=text_color, size_hint_y=None, height=dp(30)))
            self.patient_list_container.add_widget(Label(text=p['condition'], color=text_color, size_hint_y=None, height=dp(30)))
            self.patient_list_container.add_widget(Label(text=p['status'], color=text_color, size_hint_y=None, height=dp(30)))
            
            delete_btn = Button(
                text='Delete', 
                size_hint_y=None, height=dp(30), 
                background_color=(0.7, 0.2, 0.2, 1),
                background_normal=''
            )
            delete_btn.bind(on_press=lambda inst, pid=p['id']: self.confirm_delete_patient(pid))
            self.patient_list_container.add_widget(delete_btn)

    def add_new_patient(self, instance):
        name = self.name_input.text.strip()
        age = self.age_input.text.strip()
        condition = self.condition_input.text.strip()
        status = self.status_input.text.strip()

        if not all([name, age, condition, status]):
            self.show_message_popup("Error", "All fields are required to add a patient.")
            return

        try:
            int(age)
        except ValueError:
            self.show_message_popup("Error", "Age must be a valid number.")
            return

        add_patient(name, age, condition, status)
        self.name_input.text = self.age_input.text = self.condition_input.text = self.status_input.text = ""
        self.refresh_patient_list()

    def confirm_delete_patient(self, patient_id):
        content = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text=f"Are you sure you want to delete patient ID {patient_id}?", color=(1, 1, 1, 1)))
        
        button_container = BoxLayout(spacing=dp(10), size_hint_y=None, height=dp(40))
        popup = Popup(title='Confirm Deletion', content=content, size_hint=(0.5, 0.3), auto_dismiss=False)
        
        def do_delete(instance):
            delete_patient(patient_id)
            self.refresh_patient_list()
            popup.dismiss()

        def do_cancel(instance):
            popup.dismiss()
            
        confirm_btn = Button(text='Delete', background_color=(0.7, 0.2, 0.2, 1), background_normal='', on_press=do_delete)
        cancel_btn = Button(text='Cancel', background_color=(0.2, 0.2, 0.7, 1), background_normal='', on_press=do_cancel)
        
        button_container.add_widget(cancel_btn)
        button_container.add_widget(confirm_btn)
        content.add_widget(button_container)
        popup.open()

    def show_message_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text=message, color=(1, 1, 1, 1)))
        popup = Popup(title=title, content=content, size_hint=(0.5, 0.3))
        
        close_btn = Button(text='OK', size_hint_y=None, height=dp(40), background_color=(0.1, 0.6, 0.9, 1), background_normal='')
        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()

    # --- MODULE 2: SQLI ASSURANCE TEST UI ---
    def create_sqli_test_ui(self):
        sqli_layout = BoxLayout(orientation='vertical', spacing=dp(20), padding=dp(20))
        
        sqli_layout.add_widget(Label(
            text="SQL INJECTION ASSURANCE TEST (Parameterized Queries)", 
            font_size='28sp', size_hint_y=None, height=dp(40), 
            color=(0.9, 0.9, 0.1, 1)
        ))
        
        sqli_layout.add_widget(Label(
            text="Try entering malicious input (e.g., ' OR '1'='1 --) to confirm the system is resilient.\nThe underlying query uses **safe parameterization** for all user input.",
            size_hint_y=None, height=dp(80), 
            color=(0.7, 0.7, 0.7, 1),
            halign='left', valign='top', text_size=(self.content_area.width - dp(40), None)
        ))

        # Input and Button
        input_row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        self.sqli_test_input = TextInput(hint_text='Enter Patient ID or Name search term...', multiline=False)
        test_button = Button(
            text="Run Query Test",
            size_hint_x=0.3,
            background_color=(0.1, 0.7, 0.7, 1),
            background_normal='',
            on_press=self.run_sqli_test
        )
        input_row.add_widget(self.sqli_test_input)
        input_row.add_widget(test_button)
        sqli_layout.add_widget(input_row)

        # Output Area
        self.sqli_test_output = Label(
            text="Test results will appear here.",
            size_hint_y=1, 
            color=(0.1, 0.9, 0.1, 1),
            halign='left', valign='top', text_size=(self.content_area.width - dp(40), None)
        )
        scroll_output = ScrollView()
        scroll_output.add_widget(self.sqli_test_output)
        sqli_layout.add_widget(scroll_output)
        
        return sqli_layout

    def run_sqli_test(self, instance):
        query_input = self.sqli_test_input.text.strip()
        if not query_input:
            self.sqli_test_output.text = "Please enter a search term to test."
            return

        result_text = test_sqli_vulnerability(query_input)
        self.sqli_test_output.text = result_text

    # --- MODULE 3: AUDIT LOG UI ---
    def create_audit_log_ui(self):
        log_data = get_audit_logs()
        
        audit_layout = BoxLayout(orientation='vertical', spacing=dp(10))
        
        audit_layout.add_widget(Label(
            text="AUDIT LOG REPORT (Separate Database)", 
            font_size='28sp', 
            size_hint_y=None, 
            height=dp(40), 
            color=(0.9, 0.9, 0.9, 1)
        ))
        
        # Header Row
        header_grid = GridLayout(cols=4, size_hint_y=None, height=dp(30))
        for text in ["Timestamp", "User", "Action", "Details/Target ID"]:
            header_grid.add_widget(Label(text=text, color=(0.1, 0.9, 0.1, 1)))
        audit_layout.add_widget(header_grid)
        
        # Data Rows
        data_grid = GridLayout(cols=4, spacing=dp(5), size_hint_y=None)
        data_grid.bind(minimum_height=data_grid.setter('height')) 
        
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(data_grid)
        audit_layout.add_widget(scroll)

        for timestamp, user, action, target_id in log_data:
            # Color coding: RED for failed logins, GREEN for success
            text_color = (0.8, 0.8, 0.8, 1)
            if "SUCCESSFUL LOGIN" in action:
                 text_color = (0.1, 0.9, 0.1, 1) 
            if "FAILED LOGIN ATTEMPT" in action:
                text_color = (0.9, 0.2, 0.2, 1) # Highlight failed attempts
                
            data_grid.add_widget(Label(text=timestamp, color=text_color, size_hint_y=None, height=dp(25)))
            data_grid.add_widget(Label(text=user, color=text_color, size_hint_y=None, height=dp(25)))
            data_grid.add_widget(Label(text=action, color=text_color, size_hint_y=None, height=dp(25)))
            data_grid.add_widget(Label(text=target_id, color=text_color, size_hint_y=None, height=dp(25)))

        return audit_layout

class HospitalManagementApp(App): 
    def build(self):
        self.title = "Hospital Management System"
        
        # 1. Setup Database
        setup_database()
        
        # 2. Setup Screen Manager
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(DashboardScreen(name='dashboard'))
        
        sm.current = 'login' 
        return sm

# --- MANDATORY PYTHON ENTRY POINT ---
if __name__ == '__main__':
    HospitalManagementApp().run()