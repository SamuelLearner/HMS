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

try:
    KEY = load_or_generate_key()
    CIPHER_SUITE = Fernet(KEY)
except Exception as e:
    print(f"Error initializing encryption: {e}")
    CIPHER_SUITE = None

def encrypt_data(data):
    """Encrypts a string (for PHI fields)."""
    if CIPHER_SUITE:
        return CIPHER_SUITE.encrypt(data.encode('utf-8'))
    return data.encode('utf-8')

def decrypt_data(token):
    """Decrypts a Fernet token (bytes) back to a string."""
    if CIPHER_SUITE:
        try:
            return CIPHER_SUITE.decrypt(token).decode('utf-8')
        except Exception:
            # Handle cases where data might be unencrypted bytes
            return token.decode('utf-8', errors='ignore') 
    return token.decode('utf-8', errors='ignore')

# --- Logging Functionality ---
def setup_users_table():
    conn = sqlite3.connect(PATIENT_DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Create default admin account if none exists
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", "admin123")
        )

    conn.commit()
    conn.close()

# --- 3. DUAL DATABASE AUDIT LOGGING ---

def setup_log_database():
    """Initializes the separate audit log database."""
    conn = sqlite3.connect(AUDIT_DB_NAME)
    cursor = conn.cursor()
    # Log table structure
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            timestamp TEXT NOT NULL,
            user TEXT,
            action TEXT,
            target_id TEXT,
            status TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_action(user, action, target_id="N/A", status=None):
    """Records an action into the audit log database (Secure Insertion)."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(AUDIT_DB_NAME)
    cursor = conn.cursor()
    # Using parameterization for logging itself is best practice!
    cursor.execute(
        "INSERT INTO audit_log (timestamp, user, action, target_id, status) VALUES (?, ?, ?, ?, ?)",
        (timestamp, user, action, target_id, status)
    )
    conn.commit()
    conn.close()

# --- 4. PATIENT DATA DATABASE SETUP ---

def setup_patient_database():
    """Initializes the main patient data database, ensuring all columns exist."""
    conn = sqlite3.connect(PATIENT_DB_NAME)
    cursor = conn.cursor()
    # Patient Data Table: Name and Condition MUST be stored as BLOB (encrypted bytes)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name BLOB NOT NULL, 
            age INTEGER,
            condition BLOB NOT NULL,
            date_added TEXT
        )
    """)
    conn.commit()
    conn.close()

def setup_database():
    setup_patient_database()
    setup_log_database()
    setup_users_table() 

# --- KIVY UI DEFINITIONS ---

class CustomTextInput(TextInput):
    # Custom styling for better look
    pass

class PatientRecordForm(BoxLayout):
    # This class manages the form layout and logic for adding records
    
    def __init__(self, dashboard_instance, **kwargs):
        super().__init__(**kwargs)
        self.dashboard = dashboard_instance
        self.orientation = 'vertical'
        self.spacing = dp(10)
        self.padding = dp(10)
        self.size_hint = (0.5, 1)

        # --- Kivy canvas for drawing background ---
        with self.canvas.before:
            Color(0.2, 0.2, 0.2, 1)  # Dark gray background
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(pos=self.update_rect, size=self.update_rect)
        # ------------------------------------------

        # UI elements
        self.add_widget(Label(text="[color=#FFFFFF]Add New Patient Record[/color]", font_size=dp(20), markup=True, size_hint_y=None, height=dp(30)))
        
        grid = GridLayout(cols=2, spacing=dp(10), size_hint_y=None, height=dp(180))
        
        grid.add_widget(Label(text="[color=#FFFFFF]Patient Name:[/color]", markup=True))
        self.name_input = CustomTextInput(multiline=False, size_hint_y=None, height=dp(30))
        grid.add_widget(self.name_input)
        
        grid.add_widget(Label(text="[color=#FFFFFF]Age:[/color]", markup=True))
        self.age_input = CustomTextInput(multiline=False, input_filter='int', size_hint_y=None, height=dp(30))
        grid.add_widget(self.age_input)
        
        grid.add_widget(Label(text="[color=#FFFFFF]Condition:[/color]", markup=True))
        self.condition_input = CustomTextInput(multiline=False, size_hint_y=None, height=dp(30))
        grid.add_widget(self.condition_input)
        
        self.add_widget(grid)

        self.save_button = Button(
            text='Save Encrypted Record (Test Target)', 
            size_hint_y=None, 
            height=dp(40), 
            background_color=(0.1, 0.7, 0.1, 1)
        )
        self.save_button.bind(on_release=self.save_record)
        self.add_widget(self.save_button)

        self.status_label = Label(text="", size_hint_y=None, height=dp(30), markup=True)
        self.add_widget(self.status_label)

    # Method to update the position and size of the background rectangle
    def update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size
        
    def save_record(self, instance):
        name = self.name_input.text
        age = self.age_input.text
        condition = self.condition_input.text
        user = "admin" # Assume 'admin' is logged in

        if not name or not age or not condition:
            self.status_label.text = "[color=#FF0000]Error: All fields are required.[/color]"
            log_action(user=user, action='RECORD_SUBMISSION', target_id=name, status='FAILED_EMPTY')
            return
            
        try:
            # --- CONTROL 3: AES ENCRYPTION APPLIED HERE ---
            encrypted_name = encrypt_data(name)
            encrypted_condition = encrypt_data(condition)
            date_added = datetime.now().isoformat()
            
            conn = sqlite3.connect(PATIENT_DB_NAME)
            cursor = conn.cursor()
            
            # --- CONTROL 1: SQL PARAMETERIZATION APPLIED HERE (CRITICAL FIX) ---
            # Using the placeholders (?) prevents SQL Injection by treating input as literal data.
            cursor.execute(
                "INSERT INTO patients (name, age, condition, date_added) VALUES (?, ?, ?, ?)",
                (encrypted_name, int(age), encrypted_condition, date_added)
            )
            
            conn.commit()
            record_id = cursor.lastrowid
            conn.close()
            
            self.status_label.text = f"[color=#00FF00]Record {record_id} saved and encrypted![/color]"
            
            # --- CONTROL 2: DUAL DATABASE AUDIT LOGGING APPLIED HERE ---
            log_action(user=user, action='RECORD_SUBMISSION', target_id=str(record_id))
            
            # Clear inputs and refresh list
            self.name_input.text = ''
            self.age_input.text = ''
            self.condition_input.text = ''
            self.dashboard.load_patient_records()
            
        except ValueError:
            self.status_label.text = "[color=#FF0000]Error: Age must be a number.[/color]"
            log_action(user=user, action='RECORD_SUBMISSION', target_id=name, status='FAILED_VAL_ERR')
        except Exception as e:
            self.status_label.text = f"[color=#FF0000]Error saving record: {e}[/color]"
            log_action(user=user, action='RECORD_SUBMISSION', target_id=name, status='FAILED_DB_ERR')

class DashboardScreen(Screen):
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.patient_list_layout = GridLayout(
            cols=1, # Correct: Layout for stacking individual patient rows vertically
            size_hint_y=None, 
            height=dp(100), # Placeholder, will be updated
            row_default_height=dp(50), 
            row_force_default=True,
            spacing=dp(2)
        )
        self.build_ui()
        
    def build_ui(self):
        main_layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(15))
        
        # Header
        header = Label(
            text="[color=#00AACC]HOSPITAL MANAGEMENT SYSTEM (DPRS)[/color]", 
            font_size=dp(30), 
            markup=True,
            size_hint_y=0.1
        )
        main_layout.add_widget(header)

        # Content Area
        content_area = BoxLayout(orientation='horizontal', spacing=dp(15), size_hint_y=0.8)
        
        # Left Panel: Patient Form
        self.patient_form = PatientRecordForm(self)
        content_area.add_widget(self.patient_form)

        # Right Panel: Records Display
        records_panel = BoxLayout(orientation='vertical', spacing=dp(10), size_hint=(0.5, 1))
        records_panel.add_widget(Label(text="[color=#FFFFFF]Patient Records (Decrypted View)[/color]", markup=True, size_hint_y=None, height=dp(30)))
        
        # Record List Header
        header_grid = GridLayout(cols=4, size_hint_y=None, height=dp(30), spacing=dp(5))
        header_grid.add_widget(Label(text="[color=#AAAAAA]ID[/color]", markup=True, size_hint_x=0.1))
        header_grid.add_widget(Label(text="[color=#AAAAAA]Name[/color]", markup=True, size_hint_x=0.35))
        header_grid.add_widget(Label(text="[color=#AAAAAA]Condition[/color]", markup=True, size_hint_x=0.35))
        header_grid.add_widget(Label(text="[color=#AAAAAA]Actions[/color]", markup=True, size_hint_x=0.2))
        records_panel.add_widget(header_grid)
        
        # Record Scroll View
        scroll_view = ScrollView(do_scroll_y=True, do_scroll_x=False)
        self.patient_list_layout.bind(minimum_height=self.patient_list_layout.setter('height'))
        scroll_view.add_widget(self.patient_list_layout)
        records_panel.add_widget(scroll_view)
        
        content_area.add_widget(records_panel)
        main_layout.add_widget(content_area)

        # Footer
        footer = BoxLayout(size_hint_y=0.1, spacing=dp(10))
        footer.add_widget(Button(text='View Audit Log', background_color=(0.8, 0.6, 0.2, 1), on_release=self.show_audit_log))
        footer.add_widget(Button(
    text='Add User',
    background_color=(0.2, 0.6, 0.8, 1),
    on_release=lambda x: setattr(self.manager, 'current', 'add_user')
))
        footer.add_widget(Button(text='Refresh Records', background_color=(0.4, 0.4, 0.4, 1), on_release=lambda x: self.load_patient_records()))
        footer.add_widget(Button(text='Logout', background_color=(0.8, 0.2, 0.2, 1), on_release=lambda x: setattr(self.manager, 'current', 'login'))) 
        main_layout.add_widget(footer)

        self.add_widget(main_layout)

    def on_enter(self, *args):
        self.load_patient_records()

    def load_patient_records(self):
        layout = self.patient_list_layout
        layout.clear_widgets()
        
        conn = sqlite3.connect(PATIENT_DB_NAME)
        cursor = conn.cursor()
        
        # This query requires the 'date_added' column to exist
        cursor.execute("SELECT id, name, age, condition, date_added FROM patients ORDER BY id DESC") 
        patients = cursor.fetchall()
        conn.close()
        
        if not patients:
            layout.add_widget(Label(text="[color=#AAAAAA]No records found.[/color]", markup=True, size_hint_x=1)) 
            return

        for patient in patients:
            try:
                patient_id = str(patient[0])
                # Decrypt PHI for viewing
                decrypted_name = decrypt_data(patient[1])
                decrypted_condition = decrypt_data(patient[3])

                # This item grid holds one record (row) with 4 columns
                item_grid = GridLayout(cols=4, size_hint_y=None, height=dp(48), spacing=dp(5))
                item_grid.add_widget(Label(text=patient_id, color=(1, 1, 1, 1), size_hint_x=0.1))
                item_grid.add_widget(Label(text=decrypted_name, color=(1, 1, 1, 1), size_hint_x=0.35, halign='left'))
                item_grid.add_widget(Label(text=decrypted_condition, color=(1, 1, 1, 1), size_hint_x=0.35, halign='left'))
                
                delete_btn = Button(
                    text='Delete',
                    size_hint_x=0.2,
                    background_color=(0.9, 0.3, 0.3, 1),
                    on_release=lambda btn, rid=patient_id: self.delete_record(rid)
                )
                item_grid.add_widget(delete_btn)
                
                # The item_grid (the full row) is added to the patient_list_layout (cols=1)
                layout.add_widget(item_grid) 
            except Exception as e:
                print(f"Error decrypting/loading record {patient[0]}: {e}")
                log_action(user="system", action='DECRYPT_ERROR', target_id=str(patient[0]))

    def delete_record(self, record_id):
        user = "admin"
        try:
            conn = sqlite3.connect(PATIENT_DB_NAME)
            cursor = conn.cursor()
            
            # --- CONTROL 1: SQL PARAMETERIZATION FOR DELETION ---
            cursor.execute("DELETE FROM patients WHERE id = ?", (record_id,))
            
            if cursor.rowcount > 0:
                conn.commit()
                self.load_patient_records()
                log_action(user=user, action='RECORD_DELETED', target_id=record_id)
            else:
                log_action(user=user, action='DELETE_FAILED', target_id=record_id)
                
            conn.close()
            
        except Exception as e:
            print(f"Delete Error: {e}")
            log_action(user=user, action='DELETE_ERROR', target_id=record_id)
            
    def show_audit_log(self, instance):
        # Create and switch to the Audit Log screen
        self.manager.add_widget(AuditLogScreen(name='audit_log'))
        self.manager.current = 'audit_log'


class LoginScreen(Screen):
    login_status = StringProperty("Please enter credentials.")
    status_color = ListProperty([0.5, 0.5, 0.5, 1]) 

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()
        
    def build_ui(self):
        main_layout = BoxLayout(orientation='vertical', padding=dp(50), spacing=dp(20))
        
        # Header
        main_layout.add_widget(Label(text='[color=#00AACC]Hospital Management Login[/color]', font_size=dp(30), markup=True, size_hint_y=0.2))

        # Input Grid (Test Target for SQL Injection Failure Test)
        input_grid = GridLayout(cols=2, spacing=dp(15), size_hint_y=0.6)
        
        input_grid.add_widget(Label(text='[color=#FFFFFF]Username:[/color]', markup=True))
        self.username_input = CustomTextInput(multiline=False, size_hint_x=0.8)
        input_grid.add_widget(self.username_input)
            
        input_grid.add_widget(Label(text='[color=#FFFFFF]Password:[/color]', markup=True))
        self.password_input = CustomTextInput(multiline=False, password=True, size_hint_x=0.8)
        input_grid.add_widget(self.password_input)
        
        input_grid.add_widget(BoxLayout(size_hint_y=None, height=dp(1)))
        
        login_btn = Button(
            text='Login (Test Target)',
            size_hint_y=None,
            height=dp(40),
            background_color=(0.2, 0.6, 1, 1),
            on_release=lambda x: self.attempt_login(self.username_input.text, self.password_input.text)
        )
        input_grid.add_widget(login_btn)
        
        main_layout.add_widget(input_grid)
        
        # Status Label
        self.status_label = Label(text=self.login_status, size_hint_y=0.2, color=self.status_color, font_size=dp(18))
        main_layout.add_widget(self.status_label)
        
        self.add_widget(main_layout)

    def attempt_login(self, username, password):
        # The professor's point: The SQLi test must target this *live* input.
        
        if not username or not password:
            self.status_label.text = "[color=#FF0000]Error: Username and Password cannot be empty.[/color]"
            log_action(user='N/A', action='LOGIN_ATTEMPT', target_id='N/A', status='FAILED_EMPTY')
            return

        # --- CONTROL 1: SQL PARAMETERIZATION (Conceptual application) ---
        
        conn = sqlite3.connect(PATIENT_DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )

        user_record = cursor.fetchone()
        conn.close()

        if user_record:
            self.status_label.text = "[color=#00FF00]Login Successful![/color]"
            self.manager.current = 'dashboard'
            self.username_input.text = ''
            self.password_input.text = ''
            log_action(user=username, action='LOGIN_ATTEMPT', target_id='N/A', status='SUCCESS')
        else:
            self.status_label.text = "[color=#FF0000]Error: Invalid username or password.[/color]"
            log_action(user=username, action='LOGIN_ATTEMPT', target_id='N/A', status='FAILED_CREDS')

            
            
class AuditLogScreen(Screen):
    def on_enter(self, *args):
        self.clear_widgets()
        self.add_widget(self.build_log_view())

    def build_log_view(self):
        audit_layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(15))
        
        audit_layout.add_widget(Label(text="[color=#00AACC]System Audit Log (Immutable Record)[/color]", font_size=dp(24), markup=True, size_hint_y=0.1))

        conn = sqlite3.connect(AUDIT_DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, user, action, target_id, status FROM audit_log ORDER BY timestamp DESC")
        log_data = cursor.fetchall()
        conn.close()

        # Data Grid Setup
        # Set height based on number of log entries + header
        log_height = max(dp(250), dp(len(log_data) * 25) + dp(30)) 
        
        data_grid = GridLayout(
            cols=4, 
            spacing=dp(5), 
            size_hint_y=None, 
            height=log_height,
            row_default_height=dp(25),
            row_force_default=True
        )

        # Header Row
        header_colors = (0.5, 0.5, 0.5, 1)
        data_grid.add_widget(Label(text="[color=#AAAAAA]Time[/color]", markup=True, size_hint_y=None, height=dp(30), color=header_colors))
        data_grid.add_widget(Label(text="[color=#AAAAAA]User[/color]", markup=True, size_hint_y=None, height=dp(30), color=header_colors))
        data_grid.add_widget(Label(text="[color=#AAAAAA]Action[/color]", markup=True, size_hint_y=None, height=dp(30), color=header_colors))
        data_grid.add_widget(Label(text="[color=#AAAAAA]Target/Status[/color]", markup=True, size_hint_y=None, height=dp(30), color=header_colors))
        
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(data_grid)
        audit_layout.add_widget(scroll)

        for timestamp, user, action, target_id, status in log_data:
            # Color coding: RED for failed attempts, GREEN for success
            text_color = (0.8, 0.8, 0.8, 1)
            if status == "SUCCESS":
                text_color = (0.1, 0.9, 0.1, 1)
            if "RECORD_SUBMISSION" in action and target_id.isdigit(): 
                text_color = (0.1, 0.9, 0.1, 1) 
            if status and ("FAILED" in status or "ERROR" in status):
                text_color = (0.9, 0.2, 0.2, 1) 

            # Simple action view (e.g., 'LOGIN_ATTEMPT' -> 'LOGIN ATTEMPT')
            display_action = action.replace('_', ' ') 
            display_target = f"{target_id}/{status}" if status else target_id

            data_grid.add_widget(Label(text=timestamp.split(' ')[1], color=text_color, size_hint_y=None, height=dp(25)))
            data_grid.add_widget(Label(text=user, color=text_color, size_hint_y=None, height=dp(25)))
            data_grid.add_widget(Label(text=display_action, color=text_color, size_hint_y=None, height=dp(25))) 
            data_grid.add_widget(Label(text=display_target, color=text_color, size_hint_y=None, height=dp(25)))

        audit_layout.add_widget(Button(
            text='Back to Dashboard',
            size_hint_y=0.1,
            background_color=(0.4, 0.4, 0.4, 1),
            on_release=lambda x: setattr(self.manager, 'current', 'dashboard')
        ))

        return audit_layout
    
class AddUserScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()
    
    def build_ui(self):
        layout = BoxLayout(orientation='vertical', padding=dp(40), spacing=dp(20))
        
        layout.add_widget(Label(text='[color=#00AACC]Add New User[/color]', font_size=dp(30), markup=True))
        
        # Username
        layout.add_widget(Label(text='Username:', color=(1,1,1,1)))
        self.username_input = CustomTextInput(multiline=False)
        layout.add_widget(self.username_input)
        
        # Password
        layout.add_widget(Label(text='Password:', color=(1,1,1,1)))
        self.password_input = CustomTextInput(multiline=False, password=True)
        layout.add_widget(self.password_input)
        
        # Status label
        self.status_label = Label(text='', color=(1,0,0,1))
        layout.add_widget(self.status_label)
        
        # Add button
        add_btn = Button(text='Add User', size_hint_y=None, height=dp(40),
                         on_release=self.add_user)
        layout.add_widget(add_btn)
        
        # Back button
        back_btn = Button(text='Back to Dashboard', size_hint_y=None, height=dp(40),
                          on_release=lambda x: setattr(self.manager, 'current', 'dashboard'))
        layout.add_widget(back_btn)
        
        self.add_widget(layout)
    
    def add_user(self, instance):
        username = self.username_input.text.strip()
        password = self.password_input.text.strip()
        
        if not username or not password:
            self.status_label.text = "[color=#FF0000]Username and password required![/color]"
            return
        
        conn = sqlite3.connect(PATIENT_DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            self.status_label.text = "[color=#00FF00]User added successfully![/color]"
            log_action(user='admin', action='ADD_USER', target_id=username, status='SUCCESS')
        except sqlite3.IntegrityError:
            self.status_label.text = "[color=#FF0000]Username already exists![/color]"
            log_action(user='admin', action='ADD_USER', target_id=username, status='FAILED_DUP')
        finally:
            conn.close()
            
        # Clear inputs
        self.username_input.text = ''
        self.password_input.text = ''

class ScreenManagement(ScreenManager):
    pass

class HospitalManagementApp(App): 
    def build(self):
        self.title = "Hospital Management System"
        
        # 1. Setup Database
        setup_database()
        
        sm = ScreenManagement()
        
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(AddUserScreen(name='add_user'))
        sm.add_widget(DashboardScreen(name='dashboard'))
        
        sm.current = 'login'
        return sm

if __name__ == '__main__':
    HospitalManagementApp().run()
    