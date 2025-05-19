import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os

DB_FILE = "db.json"

# -------------------- JSON DB Handling --------------------

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {
        "users": {},             # "username": "hashed_password"
        "user_data": {},         # "username": {"data_id": {"encrypted_text": ..., "passkey": ...}}
        "failed_attempts": {},   # "username": {"data_id": failed_count}
        "fernet_key": None
    }

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f)

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# -------------------- Session Initialization --------------------

if "db" not in st.session_state:
    st.session_state.db = load_db()
    st.session_state.users = st.session_state.db.get("users", {})
    st.session_state.user_data = st.session_state.db.get("user_data", {})
    st.session_state.failed_attempts = st.session_state.db.get("failed_attempts", {})
    st.session_state.current_user = None

    # Load or generate Fernet key
    if not st.session_state.db.get("fernet_key"):
        st.session_state.db["fernet_key"] = Fernet.generate_key().decode()
        save_db(st.session_state.db)
    st.session_state.key = st.session_state.db["fernet_key"].encode()

cipher = Fernet(st.session_state.key)

def save_all():
    st.session_state.db["users"] = st.session_state.users
    st.session_state.db["user_data"] = st.session_state.user_data
    st.session_state.db["failed_attempts"] = st.session_state.failed_attempts
    st.session_state.db["fernet_key"] = st.session_state.key.decode()
    save_db(st.session_state.db)

# -------------------- Auth & Pages --------------------

def register_page():
    st.subheader("📝 Register")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    if st.button("Register"):
        if username in st.session_state.users:
            st.error("❌ Username already exists.")
        elif username and password:
            st.session_state.users[username] = hash_text(password)
            st.session_state.user_data[username] = {}
            st.session_state.failed_attempts[username] = {}
            save_all()
            st.success("✅ Registration successful! Please log in.")
        else:
            st.warning("⚠️ Fill in all fields.")

def login_page():
    st.subheader("🔐 Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    if st.button("Login"):
        if username in st.session_state.users and st.session_state.users[username] == hash_text(password):
            st.session_state.current_user = username
            st.success(f"✅ Welcome, {username}!")
            st.experimental_rerun()
        else:
            st.error("❌ Invalid username or password.")

def logout():
    st.session_state.current_user = None
    st.experimental_rerun()

def home_page():
    st.subheader(f"🏠 Welcome, {st.session_state.current_user}!")
    st.markdown("""
    ### 🔐 Features:
    - Encrypt & store sensitive data per user
    - Retrieve data using a passkey
    - Auto logout after 3 wrong attempts
    - All info is saved permanently using a JSON DB
    """)
    if st.button("Logout"):
        logout()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def store_data_page():
    st.subheader("📦 Store Data")
    data_id = st.text_input("Data ID:")
    text = st.text_area("Enter the data:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if not all([data_id, text, passkey]):
            st.warning("⚠️ All fields are required.")
            return

        user = st.session_state.current_user
        if data_id in st.session_state.user_data[user]:
            st.error("⚠️ This Data ID already exists.")
            return

        encrypted = encrypt_data(text)
        hashed_pass = hash_text(passkey)

        st.session_state.user_data[user][data_id] = {
            "encrypted_text": encrypted,
            "passkey": hashed_pass
        }
        st.session_state.failed_attempts[user][data_id] = 0
        save_all()

        st.success("✅ Data stored securely.")
        st.text_area("🔒 Encrypted Output:", value=encrypted)

def retrieve_data_page():
    st.subheader("🔍 Retrieve Data")
    data_id = st.text_input("Data ID:")
    passkey = st.text_input("Passkey:", type="password")

    if st.button("Decrypt"):
        user = st.session_state.current_user
        data_records = st.session_state.user_data.get(user, {})
        attempts = st.session_state.failed_attempts.get(user, {}).get(data_id, 0)

        if data_id not in data_records:
            st.error("❌ Data ID not found.")
            return

        if attempts >= 3:
            st.error("🚫 Too many failed attempts. You have been logged out.")
            logout()
            return

        stored = data_records[data_id]
        if stored["passkey"] == hash_text(passkey):
            decrypted = decrypt_data(stored["encrypted_text"])
            st.success("✅ Decryption successful!")
            st.write(f"📄 Decrypted Data:\n{decrypted}")
            st.session_state.failed_attempts[user][data_id] = 0
        else:
            st.session_state.failed_attempts[user][data_id] = attempts + 1
            remaining = 3 - st.session_state.failed_attempts[user][data_id]
            st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")

        save_all()

# -------------------- App Layout --------------------

st.title("🛡️ Secure Multi-User Data Vault")

if not st.session_state.current_user:
    page = st.sidebar.radio("Choose Option", ["Login", "Register"])
    login_page() if page == "Login" else register_page()
else:
    st.sidebar.write(f"👤 Logged in as: `{st.session_state.current_user}`")
    nav = st.sidebar.radio("Navigation", ["Home", "Store Data", "Retrieve Data", "Logout"])
    if nav == "Home":
        home_page()
    elif nav == "Store Data":
        store_data_page()
    elif nav == "Retrieve Data":
        retrieve_data_page()
    elif nav == "Logout":
        logout()
