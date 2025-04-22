import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# ------- SETUP -------

# Dark Theme CSS
st.markdown("""
    <style>
        body {
            background-color: #0e1117;
            color: #c7d5e0;
        }
        .stTextInput>div>div>input {
            background-color: #1f222a;
            color: white;
        }
        .stTextArea>div>textarea {
            background-color: #1f222a;
            color: white;
        }
        .stButton>button {
            background-color: #5c5c8a;
            color: white;
            border-radius: 10px;
        }
    </style>
""", unsafe_allow_html=True)

# Encryption key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

with open("secret.key", "rb") as key_file:
    KEY = key_file.read()

cipher = Fernet(KEY)

# Initialize files
USER_FILE = "users.json"
DATA_FILE = "data.json"

if not os.path.exists(USER_FILE):
    with open(USER_FILE, "w") as file:
        json.dump({}, file)

if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as file:
        json.dump({}, file)

# Load data
with open(USER_FILE, "r") as file:
    users = json.load(file)

with open(DATA_FILE, "r") as file:
    stored_data = json.load(file)

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ------- FUNCTIONS -------

def save_users():
    with open(USER_FILE, "w") as file:
        json.dump(users, file)

def save_data():
    with open(DATA_FILE, "w") as file:
        json.dump(stored_data, file)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def logout():
    st.session_state.authenticated = False
    st.session_state.username = ""
    st.session_state.failed_attempts = 0
    st.rerun()


# ------- UI PAGES -------

def login_page():
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users and users[username]["password"] == hash_password(password):
            st.success("✅ Logged in successfully!")
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.rerun()

        else:
            st.error("❌ Invalid username or password")
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= 3:
                st.warning("🚫 Too many failed attempts! Try Reset Password.")

def signup_page():
    st.subheader("🆕 Sign Up")
    username = st.text_input("Create Username")
    password = st.text_input("Create Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Sign Up"):
        if username in users:
            st.error("⚠️ Username already exists!")
        elif password != confirm_password:
            st.error("⚠️ Passwords do not match!")
        elif username and password:
            users[username] = {"password": hash_password(password)}
            save_users()
            st.success("✅ User created successfully! Now Login.")
        else:
            st.error("⚠️ Please fill all fields.")

def reset_password_page():
    st.subheader("🔄 Reset Password")
    username = st.text_input("Enter Your Username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm New Password", type="password")

    if st.button("Reset"):
        if username in users:
            if new_password == confirm_password:
                users[username]["password"] = hash_password(new_password)
                save_users()
                st.success("✅ Password reset successfully!")
            else:
                st.error("⚠️ Passwords do not match.")
        else:
            st.error("⚠️ Username not found.")

def home_page():
    st.subheader(f"🏠 Welcome, {st.session_state.username}!")
    st.write("Securely store and retrieve your private data.")

def store_data_page():
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    if st.button("Encrypt & Save"):
        if user_data:
            encrypted_text = encrypt_data(user_data)
            if st.session_state.username not in stored_data:
                stored_data[st.session_state.username] = []
            stored_data[st.session_state.username].append(encrypted_text)
            save_data()
            st.success("✅ Data encrypted and saved!")

def retrieve_data_page():
    st.subheader("🔍 Retrieve Your Data")
    if st.session_state.username in stored_data:
        for idx, enc_data in enumerate(stored_data[st.session_state.username], start=1):
            decrypted_text = decrypt_data(enc_data)
            st.write(f"**{idx}. {decrypted_text}**")
    else:
        st.info("ℹ️ No data found.")

# ------- MAIN PAGE -------

st.title("🛡️ Multi-User Secure Data Encryption System")

menu = ["Login", "Sign Up", "Reset Password"]
if st.session_state.authenticated:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]

choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Login":
    login_page()

elif choice == "Sign Up":
    signup_page()

elif choice == "Reset Password":
    reset_password_page()

elif choice == "Home":
    home_page()

elif choice == "Store Data":
    store_data_page()

elif choice == "Retrieve Data":
    retrieve_data_page()

elif choice == "Logout":
    logout()

