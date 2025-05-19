import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Memorization function
stored_data = {} # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
failed_attempts = 0 # {"user1": 3}

# Function to hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
# Function to encrypt the data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()
# Function to decrypt the data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)
    
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts[key] = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    failed_attempts[key] += 1
    return None

# Streamlit app UI
st.title("🔒 Secure Data Encryption System")
# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data Encryption System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
elif choice == "Store Data":
    st.subheader("🔐 Store Data Securely")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a unique passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("✅ Data encrypted and stored successfully!")
        else:
            st.error("⚠️ Please enter both! 'Data' and 'Passkey'.")
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Enter Encrypted Data: ")
    passkey = st.text_input("Enter Passkey:", type="password")
    
    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("⚠️ Too many failed attempts! Redirecting to Home.")
                    st.experimental_rerun()
        else:
            st.error(f"⚠️ Please enter both! 'Encrypted Data' and 'Passkey'.")
elif choice == "Login":
    st.subheader("🔑 Login")
    login_pass = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Login successful!")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password! Please try again.")