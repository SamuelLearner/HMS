import csv
import os
import base64
from datetime import datetime

# --- SECURITY SETUP & IMPORTS ---

# 1. Placeholder class is defined unconditionally
class DummyFernet:
    def __init__(self, key): pass
    def encrypt(self, data): return data.encode() # Mimic Fernet outputting bytes
    def decrypt(self, data): return data # Data might be bytes or str, depends on input

# 2. Flag to track if the real library is installed
IS_CRYPTO_INSTALLED = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    IS_CRYPTO_INSTALLED = True
except ImportError:
    print("WARNING: 'cryptography' library not found. Data will be saved UNENCRYPTED. Please run: pip install cryptography")
    # If import fails, we assign the Dummy class to Fernet
    Fernet = DummyFernet 

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.graphics import Color, Rectangle

# --- Configuration ---
Window.clearcolor = (0.95, 0.95, 0.95, 1) 
Window.size = (1000, 700)

# Define file paths
USER_FILE = 'users.csv'
CONFIG_FILE = 'constant.csv'
RECORD_FILE = 'patient_records.csv'
ENCRYPTION_KEY_FILE = 'secret.key' # File to store the Fernet key
RECORD_HEADER = ['record_id', 'patient_name', 'date', 'doctor', 'diagnosis', 'health_condition']
FERNET_KEY = None # Global variable to hold the loaded key
CIPHER_SUITE = None # Global Fernet object

# --- Core Security Functions ---

def load_or_generate_key():
    """Loads the key from ENCRYPTION_KEY_FILE or generates a new one."""
    global FERNET_KEY
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            FERNET_KEY = f.read()
            print("Encryption key loaded successfully.")
    else:
        # Generate and save a new key
        FERNET_KEY = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(FERNET_KEY)
        print("New encryption key generated and saved.")
    
    global CIPHER_SUITE
    # Initialize the Fernet cipher suite ONLY if the library is installed
    if IS_CRYPTO_INSTALLED:
        CIPHER_SUITE = Fernet(FERNET_KEY)

# Load the key immediately when the script starts
load_or_generate_key()

def encrypt_data(data_string):
    """Encrypts a string using the global CIPHER_SUITE."""
    if CIPHER_SUITE:
        try:
            # Encode string to bytes, then encrypt
            # Note: We ensure the input is always a string before encoding
            token = CIPHER_SUITE.encrypt(str(data_string).encode('utf-8'))
            return token.decode('utf-8') # Return as a string for CSV storage
        except Exception as e:
            # This path handles issues like corrupted keys/tokens, returning plaintext if encryption fails
            print(f"Encryption failed: {e}. Returning unencrypted data.")
            return str(data_string)
    return str(data_string)

def decrypt_data(token_string):
    """Decrypts an encrypted string (token) using the global CIPHER_SUITE."""
    if CIPHER_SUITE:
        try:
            # We must work with bytes for Fernet. Assume the string is a base64 encoded token.
            decrypted_bytes = CIPHER_SUITE.decrypt(token_string.encode('utf-8'))
            return decrypted_bytes.decode('utf-8') # Return as a string
        except Exception as e:
            # This handles cases where the data isn't a valid token or key is wrong
            # The data may have been written unencrypted initially, so return raw token
            print(f"Decryption failed ({e}). Returning raw data/token.")
            return token_string
    return token_string 


# --- Utility Functions (Updated for Encryption) ---

def load_data_from_csv(filepath):
    """Loads all rows from a CSV file, decrypting non-header rows."""
    if not os.path.exists(filepath):
        return []
    
    decrypted_data = []
    try:
        with open(filepath, mode='r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            raw_data = list(reader)

            if not raw_data:
                return []

            # 1. Keep the header row (raw_data[0]) unencrypted
            decrypted_data.append(raw_data[0]) 

            # 2. Decrypt all subsequent data rows
            for row in raw_data[1:]:
                if row:
                    decrypted_row = []
                    for item in row:
                        decrypted_row.append(decrypt_data(item))
                    decrypted_data.append(decrypted_row)
            return decrypted_data
            
    except Exception as e:
        print(f"Error loading and decrypting {filepath}: {e}")
        return []

def save_data_to_csv(filepath, data):
    """Encrypts non-header rows and saves data to a CSV file."""
    if not data:
        return
        
    encrypted_data = []
    
    # 1. Keep the header row (data[0]) unencrypted
    encrypted_data.append(data[0])

    # 2. Encrypt all subsequent data rows
    for row in data[1:]:
        if row:
            encrypted_row = []
            for item in row:
                # Encrypt each cell of the data row
                encrypted_row.append(encrypt_data(item))
            encrypted_data.append(encrypted_row)

    try:
        with open(filepath, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(encrypted_data)
        print(f"Data saved and encrypted to {filepath}")
    except Exception as e:
        print(f"Error saving encrypted data to {filepath}: {e}")


def load_config():
    """Loads configuration data from constant.csv."""
    config = {}
    if os.path.exists(CONFIG_FILE):
        # We load this file assuming it was not encrypted for simplicity
        try:
            with open(CONFIG_FILE, mode='r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                data = list(reader)
                if data:
                    for row in data:
                        if len(row) >= 2:
                            config[row[0].strip()] = row[1].strip()
        except Exception as e:
             print(f"Error loading {CONFIG_FILE}: {e}")

    return config

def load_user_credentials():
    """Loads username and password data from users.csv."""
    users = {}
    if not os.path.exists(USER_FILE):
        print(f"User file {USER_FILE} not found. Creating default admin user.")
        # Note: We save this file as plaintext for easy login/password management
        save_data_to_csv(USER_FILE, [['username', 'password', 'role'], ['admin1', 'securepass', 'Admin']])
    
    # We load this file assuming it was not encrypted for simplicity (passwords should be hashed)
    try:
        with open(USER_FILE, mode='r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            data = list(reader)
            if data and len(data) > 1:
                for row in data[1:]:
                    if len(row) >= 3:
                        users[row[0]] = {'password': row[1], 'role': row[2]}
    except Exception as e:
        print(f"Error loading {USER_FILE}: {e}")
            
    return users

# --- Global State ---
USER_CREDENTIALS = load_user_credentials()
CURRENT_USER = None 
CONFIG = load_config()

# Ensure patient records file exists with header
if not os.path.exists(RECORD_FILE):
    # This ensures the header is written to the file before any data is encrypted
    save_data_to_csv(RECORD_FILE, [RECORD_HEADER])


# --- Custom Layout with Background for Headers ---

class BackgroundBoxLayout(BoxLayout):
    """A BoxLayout that can draw a solid background color using the canvas."""
    def __init__(self, bg_color, **kwargs):
        super().__init__(**kwargs)
        self.bg_color = bg_color
        
        with self.canvas.before:
            Color(*self.bg_color)
            self.rect = Rectangle(size=self.size, pos=self.pos)
        
        self.bind(size=self._update_rect, pos=self._update_rect)

    def _update_rect(self, instance, value):
        self.rect.pos = instance.pos
        self.rect.size = instance.size


# --- Kivy Screens (Rest of the app remains the same, but now uses encrypted I/O) ---

class LoginScreen(Screen):
    """Screen for user authentication."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'login'
        
        main_layout = BoxLayout(orientation='vertical', padding=dp(50), spacing=dp(30))
        
        main_layout.add_widget(Label(
            text='Community Health Records', 
            font_size=dp(36), 
            size_hint_y=None, 
            height=dp(80), 
            color=(0.1, 0.1, 0.1, 1)
        ))

        form_layout = GridLayout(cols=2, spacing=dp(15), size_hint=(0.4, 0.4), pos_hint={'center_x': 0.5})

        self.username_input = TextInput(hint_text='Username', size_hint_y=None, height=dp(40), font_size=dp(18), multiline=False)
        self.password_input = TextInput(hint_text='Password', password=True, size_hint_y=None, height=dp(40), font_size=dp(18), multiline=False)
        
        label_style = {'font_size': dp(20), 'color': (0.2, 0.2, 0.2, 1), 'valign': 'middle', 'halign': 'right'}
        
        form_layout.add_widget(Label(text='Username:', **label_style))
        form_layout.add_widget(self.username_input)
        form_layout.add_widget(Label(text='Password:', **label_style))
        form_layout.add_widget(self.password_input)
        
        login_button = Button(text='Login', size_hint=(0.4, None), height=dp(50), pos_hint={'center_x': 0.5})
        login_button.bind(on_press=self.do_login)
        
        self.status_label = Label(text='', size_hint_y=None, height=dp(30), color=(1, 0, 0, 1))

        main_layout.add_widget(form_layout)
        main_layout.add_widget(login_button)
        main_layout.add_widget(self.status_label)
        main_layout.add_widget(BoxLayout(size_hint_y=0.4))

        self.add_widget(main_layout)

    def do_login(self, instance):
        global CURRENT_USER
        username = self.username_input.text
        password = self.password_input.text
        
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username]['password'] == password:
            CURRENT_USER = {'username': username, 'role': USER_CREDENTIALS[username]['role']}
            self.manager.get_screen('dashboard').update_dashboard()
            self.manager.current = 'dashboard'
            self.status_label.text = ''
            self.username_input.text = ''
            self.password_input.text = ''
        else:
            self.status_label.text = 'Invalid username or password.'

class DashboardScreen(Screen):
    """Main application dashboard."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'dashboard'
        
        self.main_layout = BoxLayout(orientation='vertical')
        self.add_widget(self.main_layout)
        self.update_dashboard()

    def update_dashboard(self, *args):
        self.main_layout.clear_widgets()

        if not CURRENT_USER:
            return

        # 1. Header 
        header_color = (0.1, 0.3, 0.5, 1) # Dark Blue
        header_layout = BackgroundBoxLayout(
            bg_color=header_color, 
            orientation='horizontal', 
            size_hint_y=None, 
            height=dp(60), 
            padding=dp(10), 
            spacing=dp(10)
        )
        
        header_layout.add_widget(Label(
            text=CONFIG.get('Hospital_Title', 'Community Health Records'), 
            font_size=dp(24), 
            color=(1, 1, 1, 1), 
            size_hint_x=0.4, 
            halign='left'
        ))

        user_info_label = Label(
            text=f'Logged in as: {CURRENT_USER["username"]} | Role: {CURRENT_USER["role"]}',
            font_size=dp(16), 
            color=(1, 1, 1, 1),
            size_hint_x=0.5,
            halign='center'
        )
        header_layout.add_widget(user_info_label)

        logout_button = Button(text='Logout', size_hint_x=0.1, on_press=self.do_logout, 
                               background_color=(0.8, 0.2, 0.2, 1), color=(1, 1, 1, 1), font_size=dp(16))
        header_layout.add_widget(logout_button)

        self.main_layout.add_widget(header_layout)

        # 2. Main Content Area
        content_layout = BoxLayout(orientation='horizontal')
        
        nav_panel = BoxLayout(orientation='vertical', size_hint_x=0.25, padding=dp(15), spacing=dp(15))
        
        nav_panel.add_widget(Button(
            text='Manage Patient Records', 
            size_hint_y=None, height=dp(60), 
            on_press=self.go_to_records,
            background_color=(0.1, 0.5, 0.8, 1), color=(1, 1, 1, 1), font_size=dp(18)
        ))
        
        nav_panel.add_widget(BoxLayout()) 
        content_layout.add_widget(nav_panel)

        info_panel = BoxLayout(orientation='vertical', size_hint_x=0.75, padding=dp(20), spacing=dp(15))
        
        info_panel.add_widget(Label(text='Hospital Management System Dashboard', font_size=dp(30), size_hint_y=None, height=dp(50), color=(0.1, 0.1, 0.1, 1)))
        
        config_grid = GridLayout(cols=2, size_hint_y=0.5, padding=dp(10), spacing=(dp(10), dp(5)))
        
        config_grid.add_widget(Label(text='--- System Configuration ---', font_size=dp(20), size_hint_y=None, height=dp(30), color=(0.3, 0.3, 0.3, 1), size_hint_x=1.0))
        
        base_width = Window.width * 0.75
        key_width = base_width * 0.4 - dp(20)
        value_width = base_width * 0.6 - dp(20)

        for key, value in CONFIG.items():
            config_grid.add_widget(Label(
                text=key + ':', 
                halign='right', 
                valign='top',
                text_size=(key_width, None), 
                size_hint_x=0.4, 
                color=(0.2, 0.2, 0.2, 1)
            ))
            config_grid.add_widget(Label(
                text=value, 
                halign='left', 
                valign='top',
                text_size=(value_width, None), 
                size_hint_x=0.6, 
                color=(0.1, 0.1, 0.1, 1)
            ))

        # Add key visibility section for evidence
        config_grid.add_widget(Label(text='--- Security Status ---', font_size=dp(20), size_hint_y=None, height=dp(30), color=(0.3, 0.3, 0.3, 1), size_hint_x=1.0))

        security_status = 'Active (cryptography installed)' if IS_CRYPTO_INSTALLED else 'INACTIVE (cryptography missing)'
        security_color = (0.2, 0.6, 0.2, 1) if IS_CRYPTO_INSTALLED else (0.8, 0.2, 0.2, 1)
        
        config_grid.add_widget(Label(text='Encryption Status:', halign='right', color=(0.2, 0.2, 0.2, 1), size_hint_x=0.4))
        config_grid.add_widget(Label(text=security_status, halign='left', color=security_color, size_hint_x=0.6))
        
        # Display the key (encoded) for evidence purposes
        key_display = FERNET_KEY.decode('utf-8') if FERNET_KEY else "Key not generated."
        config_grid.add_widget(Label(text='Fernet Key (Base64):', halign='right', color=(0.2, 0.2, 0.2, 1), size_hint_x=0.4))
        config_grid.add_widget(Label(
            text=key_display, 
            halign='left', 
            valign='top',
            text_size=(value_width, None), 
            font_size=dp(10), # Smaller font for the key
            color=(0.1, 0.1, 0.1, 1), 
            size_hint_x=0.6
        ))

        info_panel.add_widget(config_grid)

        info_panel.add_widget(BoxLayout()) # Filler space

        content_layout.add_widget(info_panel)
        self.main_layout.add_widget(content_layout)

    def do_logout(self, instance):
        global CURRENT_USER
        CURRENT_USER = None
        self.manager.current = 'login'

    def go_to_records(self, instance):
        self.manager.get_screen('records').load_records()
        self.manager.current = 'records'


class RecordView(Screen):
    """Screen for managing patient records."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'records'
        self.records = []
        self.selected_record = None

        self.main_layout = BoxLayout(orientation='vertical')
        self.add_widget(self.main_layout)

        self.build_screen()

    def build_screen(self):
        self.main_layout.clear_widgets()

        # 1. Header 
        header_color = (0.1, 0.3, 0.5, 1) 
        header_layout = BackgroundBoxLayout(
            bg_color=header_color, 
            orientation='horizontal', 
            size_hint_y=None, 
            height=dp(60), 
            padding=dp(10), 
            spacing=dp(10)
        )
        
        header_layout.add_widget(Label(
            text=CONFIG.get('Hospital_Title', 'Community Health Records'), 
            font_size=dp(24), 
            color=(1, 1, 1, 1), 
            size_hint_x=0.4, 
            halign='left'
        ))

        user_info_label = Label(
            text=f'User: {CURRENT_USER["username"]} | Role: {CURRENT_USER["role"]}' if CURRENT_USER else '',
            font_size=dp(16), 
            color=(1, 1, 1, 1),
            size_hint_x=0.5,
            halign='center'
        )
        header_layout.add_widget(user_info_label)

        logout_button = Button(text='Logout', size_hint_x=0.1, on_press=self.do_logout, 
                               background_color=(0.8, 0.2, 0.2, 1), color=(1, 1, 1, 1), font_size=dp(16))
        header_layout.add_widget(logout_button)

        self.main_layout.add_widget(header_layout)


        # 2. Content Area
        content_layout = BoxLayout(orientation='horizontal')
        
        action_panel = BoxLayout(orientation='vertical', size_hint_x=0.25, padding=dp(15), spacing=dp(15))
        
        action_panel.add_widget(Label(text='Patient Records', font_size=dp(24), size_hint_y=None, height=dp(40), color=(0.1, 0.1, 0.1, 1)))

        action_panel.add_widget(Button(
            text='Add New Record', 
            size_hint_y=None, height=dp(60), 
            on_press=self.go_to_add_record,
            background_color=(0.2, 0.6, 0.2, 1), color=(1, 1, 1, 1), font_size=dp(18)
        ))
        
        self.records_list_container = BoxLayout(orientation='vertical', spacing=dp(5), padding=(0, dp(10), 0, 0))
        scroll_view = ScrollView(size_hint=(1, 1))
        scroll_view.add_widget(self.records_list_container)
        action_panel.add_widget(scroll_view)

        content_layout.add_widget(action_panel)

        self.details_panel = BoxLayout(orientation='vertical', size_hint_x=0.75, padding=dp(20), spacing=dp(15))
        self.details_panel.add_widget(Label(text='Select a record to view details', color=(0.3, 0.3, 0.3, 1), font_size=dp(20)))
        content_layout.add_widget(self.details_panel)

        self.main_layout.add_widget(content_layout)

    def do_logout(self, instance):
        global CURRENT_USER
        CURRENT_USER = None
        self.manager.current = 'login'

    def load_records(self, *args):
        """Loads and displays patient records (now automatically decrypts)."""
        try:
            # load_data_from_csv now handles decryption automatically
            data = load_data_from_csv(RECORD_FILE)
            
            if not data or len(data) <= 1:
                self.records = []
            else:
                header = data[0]
                data_rows = data[1:]
                    
                # Map rows to dictionaries using the expected header
                self.records = [dict(zip(RECORD_HEADER, row)) for row in data_rows if len(row) == len(RECORD_HEADER)]

            self.display_records()

        except Exception as e:
            error_message = f"Error loading records: {e}"
            print(error_message)
            self.details_panel.clear_widgets()
            self.details_panel.add_widget(Label(text=error_message, color=(1, 0, 0, 1), font_size=dp(16)))

    def display_records(self):
        """Populates the records list in the left panel."""
        self.records_list_container.clear_widgets()
        
        if not self.records:
            self.records_list_container.add_widget(Label(text="No patient records available.", color=(0.3, 0.3, 0.3, 1), size_hint_y=None, height=dp(40)))
            return
        
        COL_WIDTHS = [0.15, 0.45, 0.2, 0.2] 
        
        header_grid = GridLayout(cols=4, size_hint_y=None, height=dp(30))
        header_grid.add_widget(Label(text='ID', bold=True, color=(0.1, 0.1, 0.1, 1), size_hint_x=COL_WIDTHS[0]))
        header_grid.add_widget(Label(text='Patient Name', bold=True, color=(0.1, 0.1, 0.1, 1), size_hint_x=COL_WIDTHS[1]))
        header_grid.add_widget(Label(text='Date', bold=True, color=(0.1, 0.1, 0.1, 1), size_hint_x=COL_WIDTHS[2]))
        header_grid.add_widget(Label(text='Action', bold=True, color=(0.1, 0.1, 0.1, 1), size_hint_x=COL_WIDTHS[3]))
        self.records_list_container.add_widget(header_grid)

        for record in self.records:
            record_grid_content = GridLayout(cols=4, size_hint_y=None, height=dp(40), 
                                     padding=(dp(5), 0), spacing=dp(5))
            
            record_grid_content.add_widget(Label(text=record.get('record_id', 'N/A'), color=(0.1, 0.1, 0.1, 1), size_hint_x=COL_WIDTHS[0]))
            
            patient_name_label = Label(
                text=record.get('patient_name', 'N/A'), 
                color=(0.1, 0.1, 0.1, 1), 
                size_hint_x=COL_WIDTHS[1],
                text_size=(Window.width * 0.25 * COL_WIDTHS[1] - dp(10), dp(40)),
                halign='left',
                valign='middle'
            )
            record_grid_content.add_widget(patient_name_label)
            
            record_grid_content.add_widget(Label(text=record.get('date', 'N/A'), color=(0.1, 0.1, 0.1, 1), size_hint_x=COL_WIDTHS[2]))
            
            details_btn = Button(text='View Details', size_hint_x=COL_WIDTHS[3], background_color=(0.1, 0.5, 0.8, 1), color=(1, 1, 1, 1), font_size=dp(14))
            from functools import partial
            details_btn.bind(on_press=partial(self.view_record_details, record))
            record_grid_content.add_widget(details_btn)

            row_bg_color = (0.95, 0.95, 0.95, 1) if (self.records.index(record) % 2) == 0 else (0.9, 0.9, 0.9, 1)
            row_container = BackgroundBoxLayout(
                bg_color=row_bg_color, 
                orientation='horizontal', 
                size_hint_y=None, 
                height=dp(40)
            )
            row_container.add_widget(record_grid_content)
            self.records_list_container.add_widget(row_container)

        self.records_list_container.add_widget(BoxLayout())
        
    def _update_rect(self, instance, value):
        pass

    def view_record_details(self, record, instance):
        self.selected_record = record
        self.details_panel.clear_widgets()

        self.details_panel.add_widget(Label(
            text=f'Details for Record ID: {record.get("record_id", "N/A")}', 
            font_size=dp(24), 
            size_hint_y=None, 
            height=dp(40), 
            color=(0.1, 0.1, 0.1, 1)
        ))

        details_grid = GridLayout(cols=2, spacing=(dp(15), dp(10)), size_hint_y=0.8, padding=dp(10))
        
        fields = ['patient_name', 'date', 'doctor', 'diagnosis', 'health_condition']
        
        detail_val_width = Window.width * 0.75 * 0.6 - dp(40)
        
        for field in fields:
            display_name = field.replace('_', ' ').title() + ':'
            details_grid.add_widget(Label(text=display_name, size_hint_x=0.4, halign='right', font_size=dp(18), color=(0.2, 0.2, 0.2, 1)))
            
            details_grid.add_widget(Label(
                text=record.get(field, 'N/A'), 
                size_hint_x=0.6, 
                halign='left', 
                valign='top',
                font_size=dp(18), 
                color=(0.1, 0.1, 0.1, 1),
                text_size=(detail_val_width, None)
            ))

        self.details_panel.add_widget(details_grid)
        self.details_panel.add_widget(BoxLayout())

    def go_to_add_record(self, instance):
        self.manager.get_screen('add_record').inputs['doctor'].text = CURRENT_USER['username'] if CURRENT_USER else ''
        self.manager.current = 'add_record'


class AddRecordScreen(Screen):
    """Screen for adding a new patient record."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'add_record'
        
        main_layout = BoxLayout(orientation='vertical', padding=dp(30), spacing=dp(15))
        
        main_layout.add_widget(Label(
            text='Add New Patient Record', 
            font_size=dp(30), 
            size_hint_y=None, 
            height=dp(60), 
            color=(0.1, 0.1, 0.1, 1)
        ))
        
        form_container = BoxLayout(orientation='vertical', size_hint_y=0.8, pos_hint={'center_x': 0.5})

        single_line_grid = GridLayout(cols=2, spacing=dp(15), size_hint=(0.7, None), height=dp(40*4 + 15*3), pos_hint={'center_x': 0.5})

        self.inputs = {}
        single_line_fields = [
            ('Patient Name', 'patient_name'),
            ('Date (YYYY-MM-DD)', 'date'),
            ('Doctor/Creator', 'doctor'),
            ('Diagnosis (Yes/No)', 'diagnosis'),
        ]
        
        label_style = {'font_size': dp(18), 'color': (0.2, 0.2, 0.2, 1), 'valign': 'middle', 'halign': 'right'}

        for label_text, key in single_line_fields:
            single_line_grid.add_widget(Label(text=label_text + ':', **label_style))
            
            input_widget = TextInput(
                hint_text=label_text, 
                size_hint_y=None, 
                height=dp(40), 
                font_size=dp(18), 
                multiline=False
            )
            self.inputs[key] = input_widget
            single_line_grid.add_widget(input_widget)
            
        form_container.add_widget(single_line_grid)
        
        multiline_layout = GridLayout(cols=2, spacing=dp(15), size_hint=(0.7, 0.4), pos_hint={'center_x': 0.5}, padding=(0, dp(15), 0, 0))
        
        multiline_layout.add_widget(Label(text='Health Condition:', **label_style))
        
        multiline_input = TextInput(
            hint_text='Detailed health condition (multiline)',
            size_hint_y=1.0, 
            font_size=dp(18), 
            multiline=True
        )
        self.inputs['health_condition'] = multiline_input
        multiline_layout.add_widget(multiline_input)

        form_container.add_widget(multiline_layout)

        main_layout.add_widget(form_container)
        
        self.inputs['date'].text = datetime.now().strftime('%Y-%m-%d')
        self.inputs['doctor'].text = CURRENT_USER['username'] if CURRENT_USER else ''


        button_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(60), spacing=dp(50), padding=(dp(100), dp(10), dp(100), dp(10)))
        
        save_button = Button(text='Save Record', on_press=self.save_record, background_color=(0.2, 0.6, 0.2, 1), color=(1, 1, 1, 1), font_size=dp(20))
        back_button = Button(text='Back to Records', on_press=self.go_to_records, background_color=(0.5, 0.5, 0.5, 1), color=(1, 1, 1, 1), font_size=dp(20))
        
        button_layout.add_widget(save_button)
        button_layout.add_widget(back_button)
        
        main_layout.add_widget(button_layout)
        
        self.status_label = Label(text='', size_hint_y=None, height=dp(30), color=(1, 0, 0, 1))
        main_layout.add_widget(self.status_label)
        
        main_layout.add_widget(BoxLayout())

        self.add_widget(main_layout)

    def go_to_records(self, instance):
        self.clear_inputs()
        self.manager.get_screen('records').load_records()
        self.manager.current = 'records'

    def clear_inputs(self):
        for key in self.inputs:
            if key not in ['date', 'doctor']:
                self.inputs[key].text = ''
                
        self.inputs['date'].text = datetime.now().strftime('%Y-%m-%d')
        self.status_label.text = ''

    def save_record(self, instance):
        """Handles saving the new record to CSV (data is encrypted via save_data_to_csv)."""
        record_data = {}
        for key, input_widget in self.inputs.items():
            record_data[key] = input_widget.text.strip()

        if not all(record_data.values()):
            self.status_label.text = 'ERROR: All fields must be filled.'
            return

        try:
            # Load data, which automatically decrypts it for processing
            data = load_data_from_csv(RECORD_FILE)
            
            if not data or data[0] != RECORD_HEADER:
                data = [RECORD_HEADER]

            last_id = 0
            for row in reversed(data[1:]):
                if len(row) > 0 and row[0].isdigit():
                    last_id = int(row[0])
                    break
            new_id = last_id + 1

            new_row = [
                str(new_id),
                record_data['patient_name'],
                record_data['date'],
                record_data['doctor'],
                record_data['diagnosis'],
                record_data['health_condition'].replace('\n', ' ')
            ]
            
            data.append(new_row)
            
            # Save data, which now automatically encrypts it before writing
            save_data_to_csv(RECORD_FILE, data)
            
            encryption_status_msg = " (Data is encrypted)" if IS_CRYPTO_INSTALLED else " (Data is UNENCRYPTED - install 'cryptography')"
            self.status_label.text = f'SUCCESS: Record ID {new_id} saved successfully!{encryption_status_msg}'
            self.clear_inputs()

        except Exception as e:
            self.status_label.text = f'ERROR: Failed to save record. Details: {e}'
            print(f"Save error: {e}")


# --- Main App Class ---

class HospitalApp(App):
    def build(self):
        sm = ScreenManager()
        
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(DashboardScreen(name='dashboard'))
        sm.add_widget(RecordView(name='records'))
        sm.add_widget(AddRecordScreen(name='add_record'))
        
        sm.current = 'login'
        return sm

if not os.path.exists(CONFIG_FILE):
    save_data_to_csv(CONFIG_FILE, [['Hospital_Title', 'Community Health Records']])
    CONFIG = load_config()

if __name__ == '__main__':
    HospitalApp().run()