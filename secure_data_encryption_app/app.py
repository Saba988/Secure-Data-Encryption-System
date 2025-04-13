# # app.py

# import streamlit as st
# import hashlib
# import json
# import os
# import base64
# import secrets
# from cryptography.fernet import Fernet

# # ----------------------------
# # Configuration
# # ----------------------------
# st.set_page_config(page_title="Secure Data Encryption", page_icon="🔐")
# DATA_FILE = "data.json"
# PBKDF2_ITERATIONS = 100_000

# # ----------------------------
# # Encryption Setup
# # ----------------------------
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)

# # ----------------------------
# # Utility Functions
# # ----------------------------

# # Load stored data from JSON file
# def load_data():
#     if os.path.exists(DATA_FILE):
#         with open(DATA_FILE, "r") as f:
#             return json.load(f)
#     return {}

# # Save current data state to JSON file
# def save_data(data):
#     with open(DATA_FILE, "w") as f:
#         json.dump(data, f)

# # Generate salt
# def generate_salt():
#     return base64.b64encode(secrets.token_bytes(16)).decode()

# # Hash passkey using PBKDF2
# def hash_passkey_pbkdf2(passkey, salt):
#     return base64.b64encode(
#         hashlib.pbkdf2_hmac(
#             "sha256", passkey.encode(), base64.b64decode(salt), PBKDF2_ITERATIONS
#         )
#     ).decode()

# # Encrypt text using Fernet
# def encrypt_data(text):
#     return cipher.encrypt(text.encode()).decode()

# # Decrypt data if valid credentials
# def decrypt_data(encrypted_text, passkey):
#     for entry in st.session_state.stored_data.values():
#         if entry["encrypted_text"] == encrypted_text:
#             expected_hash = hash_passkey_pbkdf2(passkey, entry["salt"])
#             if entry["passkey"] == expected_hash:
#                 st.session_state.failed_attempts = 0
#                 return cipher.decrypt(encrypted_text.encode()).decode()
#     st.session_state.failed_attempts += 1
#     return None

# # ----------------------------
# # Session Initialization
# # ----------------------------
# if "stored_data" not in st.session_state:
#     st.session_state.stored_data = load_data()

# if "failed_attempts" not in st.session_state:
#     st.session_state.failed_attempts = 0

# if "reauth_required" not in st.session_state:
#     st.session_state.reauth_required = False

# # ----------------------------
# # Navigation
# # ----------------------------
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.selectbox("Navigation", menu)

# # ----------------------------
# # Pages
# # ----------------------------
# if choice == "Home":
#     st.title("🔐 Secure Data Encryption System")
#     st.markdown("""
#     - PBKDF2-HMAC-SHA256 hashing for secure passkeys
#     - Salt used to prevent rainbow table attacks
#     - Data saved with encryption in a JSON file
#     """)

# elif choice == "Store Data":
#     st.subheader("📂 Store Data")

#     user_text = st.text_area("Enter your data:")
#     passkey = st.text_input("Set a passkey:", type="password")

#     if st.button("Encrypt & Store"):
#         if user_text and passkey:
#             encrypted = encrypt_data(user_text)
#             salt = generate_salt()
#             hashed_pass = hash_passkey_pbkdf2(passkey, salt)

#             st.session_state.stored_data[encrypted] = {
#                 "encrypted_text": encrypted,
#                 "passkey": hashed_pass,
#                 "salt": salt
#             }

#             save_data(st.session_state.stored_data)
#             st.success("✅ Data stored securely!")
#             st.code(encrypted, language="text")
#         else:
#             st.error("⚠️ Please fill in all fields.")

# elif choice == "Retrieve Data":
#     if st.session_state.reauth_required:
#         st.warning("🔒 Too many failed attempts. Please log in.")
#         st.stop()

#     st.subheader("🔍 Retrieve Data")

#     encrypted_input = st.text_area("Paste your encrypted data:")
#     passkey_input = st.text_input("Enter your passkey:", type="password")

#     if st.button("Decrypt"):
#         if encrypted_input and passkey_input:
#             result = decrypt_data(encrypted_input, passkey_input)
#             if result:
#                 st.success("✅ Decryption successful!")
#                 st.code(result)
#             else:
#                 remaining = 3 - st.session_state.failed_attempts
#                 st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
#                 if st.session_state.failed_attempts >= 3:
#                     st.session_state.reauth_required = True
#                     st.experimental_rerun()
#         else:
#             st.error("⚠️ Please provide both encrypted data and passkey.")

# elif choice == "Login":
#     st.subheader("🔑 Reauthorization Required")

#     login_pass = st.text_input("Enter master password:", type="password")

#     if st.button("Login"):
#         if login_pass == "admin123":
#             st.session_state.failed_attempts = 0
#             st.session_state.reauth_required = False
#             st.success("✅ Reauthorized successfully!")
#             # st.experimental_rerun()
#         else:
#             st.error("❌ Incorrect master password.")

import streamlit as st
import hashlib
import json
import os
import base64
import secrets
from cryptography.fernet import Fernet

# ----------------------------
# Configuration
# ----------------------------
st.set_page_config(page_title="Secure Data Encryption", page_icon="🔐")
DATA_FILE = "data.json"
KEY_FILE = "secret.key"
PBKDF2_ITERATIONS = 100_000

# ----------------------------
# Encryption Setup
# ----------------------------
def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

KEY = load_or_generate_key()
cipher = Fernet(KEY)

# ----------------------------
# Utility Functions
# ----------------------------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_salt():
    return base64.b64encode(secrets.token_bytes(16)).decode()

def hash_passkey_pbkdf2(passkey, salt):
    return base64.b64encode(
        hashlib.pbkdf2_hmac(
            "sha256", passkey.encode(), base64.b64decode(salt), PBKDF2_ITERATIONS
        )
    ).decode()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    for entry in st.session_state.stored_data.values():
        if entry["encrypted_text"] == encrypted_text:
            expected_hash = hash_passkey_pbkdf2(passkey, entry["salt"])
            if entry["passkey"] == expected_hash:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# ----------------------------
# Session Initialization
# ----------------------------
if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "reauth_required" not in st.session_state:
    st.session_state.reauth_required = False

# ----------------------------
# Navigation
# ----------------------------
menu = ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("🔧 Navigation", menu)

# ----------------------------
# Pages
# ----------------------------

if choice == "🏠 Home":
    st.title("🔐 Secure Data Encryption System")
    st.markdown("""
    Welcome to the **Secure Data Encryption System**!  
    This app allows you to securely **store** and **retrieve** sensitive information using:
    - 🔒 PBKDF2-HMAC-SHA256 for passkey hashing
    - 🧂 Salt to prevent rainbow table attacks
    - 🗄️ Encrypted JSON file storage
    - 🔐 Fernet symmetric encryption

    **Use the sidebar** to navigate through the app.  
    """)
    st.info("Tip: Use a strong passkey when storing data.")

elif choice == "📂 Store Data":
    st.subheader("📂 Encrypt & Store Data")

    user_text = st.text_area("🔤 Enter your sensitive data:")
    passkey = st.text_input("🔑 Set a passkey for retrieval:", type="password")

    if st.button("💾 Encrypt & Store"):
        if user_text and passkey:
            encrypted = encrypt_data(user_text)
            salt = generate_salt()
            hashed_pass = hash_passkey_pbkdf2(passkey, salt)

            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed_pass,
                "salt": salt
            }

            save_data(st.session_state.stored_data)
            st.success("✅ Data stored securely!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please fill in both fields.")

elif choice == "🔍 Retrieve Data":
    if st.session_state.reauth_required:
        st.warning("🔒 Too many failed attempts. Please log in.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")

    encrypted_input = st.text_area("📥 Paste your encrypted data:")
    passkey_input = st.text_input("🔑 Enter your passkey:", type="password")

    if st.button("🔓 Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Decryption successful!")
                st.code(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.reauth_required = True
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Please fill in all fields.")

elif choice == "🔑 Login":
    st.subheader("🔑 Reauthentication")

    login_pass = st.text_input("🔐 Enter master password:", type="password")

    if st.button("🔓 Login"):
        if login_pass == "admin123":  # You can later use environment variables for security
            st.session_state.failed_attempts = 0
            st.session_state.reauth_required = False
            st.success("✅ Reauthorized successfully!")
        else:
            st.error("❌ Incorrect master password.")
