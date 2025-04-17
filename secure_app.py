import json
import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os

# Encryption key generate karein
def generate_key():
    if not os.path.exists('secret.key'):
        key = Fernet.generate_key()
        with open('secret.key', 'wb') as key_file:
            key_file.write(key)
    else:
        with open('secret.key', 'rb') as key_file:
            key = key_file.read()
    return key

KEY = generate_key()
cipher = Fernet(KEY)

# Data storage with JSON backup
def load_data():
    if os.path.exists('data.json'):
        with open('data.json', 'r') as f:
            return st.session_state.get('stored_data', {})
    return {}

def save_data(data):
    with open('data.json', 'w') as f:
        json.dump(data, f)
    st.session_state.stored_data = data

stored_data = load_data()
failed_attempts = st.session_state.get('failed_attempts', 0)

# Security functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Streamlit UI
def main():
    st.title("🔒 Secure Data Encryption System")
    
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("Secure Data Storage")
        st.markdown("""
        ### How to use:
        1. **Store Data**: Encrypt your data
        2. **Retrieve Data**: Decrypt with passkey
        3. **Login**: Required after 3 failed attempts
        """)

    elif choice == "Store Data":
        st.subheader("📂 Store Data")
        user_data = st.text_area("Enter your data:")
        passkey = st.text_input("Create passkey:", type="password")
        
        if st.button("Encrypt & Save"):
            if user_data and passkey:
                encrypted = encrypt_data(user_data)
                stored_data[encrypted] = {
                    "text": user_data,
                    "passkey": hash_passkey(passkey)
                }
                save_data(stored_data)
                st.success("✅ Data stored securely!")
                st.code(f"Encrypted Data:\n{encrypted}")
            else:
                st.error("❌ Both fields are required!")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Data")
        encrypted_text = st.text_area("Paste encrypted data:")
        passkey = st.text_input("Enter passkey:", type="password")
        
        if st.button("Decrypt"):
            if encrypted_text and passkey:
                if encrypted_text in stored_data:
                    if stored_data[encrypted_text]["passkey"] == hash_passkey(passkey):
                        decrypted = decrypt_data(encrypted_text)
                        st.success("✅ Decrypted successfully!")
                        st.text_area("Your data:", value=decrypted, height=200)
                    else:
                        st.session_state.failed_attempts += 1
                        st.error(f"❌ Wrong passkey! Attempts left: {3-st.session_state.failed_attempts}")
                        if st.session_state.failed_attempts >= 3:
                            st.warning("🔒 Too many attempts! Please login.")
                            st.session_state.redirect = "Login"
                            st.experimental_rerun()
                else:
                    st.error("❌ Encrypted data not found")
            else:
                st.error("❌ Both fields are required!")

    elif choice == "Login":
        st.subheader("🔑 Re-authentication Required")
        login_pass = st.text_input("Enter admin password:", type="password")
        
        if st.button("Login"):
            if login_pass == "admin123":  # Change this in production
                st.session_state.failed_attempts = 0
                st.success("✅ Login successful!")
                st.session_state.redirect = "Retrieve Data"
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password!")

if __name__ == "__main__":
    main()