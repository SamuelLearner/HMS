import os

MAIN_FILE = os.getcwd()
# This path points to the file inside the subfolder, which you confirmed
CONSTANT_FILE = os.path.join(MAIN_FILE, "backup_&_restore_folder", "constant.csv") 
constants ={}
condition = True

# --- File Loading Logic ---
try:
    # Open the file and read line-by-line
    with open(CONSTANT_FILE, "r") as read_constant:
        while True:
            reader = read_constant.readline()
            
            # Stop if we hit the end of the file or a completely empty line
            if not reader:
                break
                
            # Skip lines that are just whitespace
            if not reader.strip():
                continue
            
            try:
                # Split the line by the comma
                reader_split = reader.split(",", 1) # Limit split to 1 to handle commas in values
                if len(reader_split) == 2:
                    name, value = reader_split
                    constants[name.strip()] = value.strip()
                else:
                    # Log if a line doesn't have exactly one comma
                    print(f"Warning: Skipping malformed line in constant.csv: {reader.strip()}")

            except Exception as e:
                # Catch general parsing errors
                print(f"Error reading constant file line: {e}")
                
except FileNotFoundError:
    print(f"FATAL ERROR: Constant file not found at {CONSTANT_FILE}. Please check file path.")
    
# --- Getter Functions ---
def get_hospital_title():
    """Returns the hospital's title from the constants."""
    return constants.get("HOSPITAL_TITLE")

def get_hospital_motto():
    """Returns the hospital's motto from the constants."""
    return constants.get("HOSPITAL_MOTTO")

def get_hospital_location():
    """Returns the hospital's location from the constants."""
    return constants.get("HOSPITAL_LOCATION")

def get_master_key():
    """Returns the master key for encryption/security."""
    # Ensure this key is returned for use in patient_record_manager.py
    return constants.get("MASTER_KEY") 

def get_total_bed():
    """Returns the total number of beds as an integer."""
    try:
        return int(constants.get("TOTAL_BED"))
    except (ValueError, TypeError):
        return 0

# --- Helper Functions ---
def grab_constant(logged_in, name):
    if logged_in:
        name = name.upper()
        return constants.get(name)

def set_constant(logged_in, constants_dict):
    if logged_in:
        with open(CONSTANT_FILE, "w") as write_constant:
            for key, value in constants_dict.items():
                write_constant.write(key.upper() + "," + str(value) + "\n")