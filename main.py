import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import time
import base64

# Global Variables
stored_data = {}  # In-memory storage for user data
failed_attempts = 0  # Track failed attempts for reauthorization
MAX_FAILED_ATTEMPTS = 3  # Max attempts before reauthorization

# Function to generate a key for Fernet encryption
def generate_key():
    return Fernet.generate_key()

# Function to encrypt data using Fernet
def encrypt_data(data, passkey):
    key = hashlib.sha256(passkey.encode()).digest()  # Get SHA256 hash of the passkey
    fernet_key = base64.urlsafe_b64encode(key)  # Convert to base64 URL-safe encoding
    fernet = Fernet(fernet_key)  # Create Fernet object with the valid key
    encrypted = fernet.encrypt(data.encode())
    return encrypted

# Function to decrypt data using Fernet
def decrypt_data(encrypted_data, passkey):
    key = hashlib.sha256(passkey.encode()).digest()  # Get SHA256 hash of the passkey
    fernet_key = base64.urlsafe_b64encode(key)  # Convert to base64 URL-safe encoding
    fernet = Fernet(fernet_key)  # Create Fernet object with the valid key
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

# Home Page - Display Options to Insert or Retrieve Data
def home_page():
    global failed_attempts
    st.title("🔐 Secure Data Storage and Retrieval System")
    
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        st.warning("Too many failed attempts! Please log in again. 🚨")
        login_page()
    else:
        option = st.selectbox("Choose an action 📝", ["Insert Data", "Retrieve Data"])
        if option == "Insert Data":
            insert_data_page()
        elif option == "Retrieve Data":
            retrieve_data_page()

# Insert Data Page - User enters data and passkey
def insert_data_page():
    global stored_data
    st.subheader("🔒 Insert Your Data Below:")
    data = st.text_area("Enter your data to store:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("💾 Save Data"):
        if data and passkey:
            encrypted_data = encrypt_data(data, passkey)
            stored_data[passkey] = {"encrypted_text": encrypted_data}
            st.success("✅ Data saved successfully!")
        else:
            st.error("❌ Please enter both data and passkey.")

# Retrieve Data Page - User enters passkey to retrieve data
def retrieve_data_page():
    global stored_data, failed_attempts
    st.subheader("🔑 Retrieve Your Data Below:")
    passkey = st.text_input("Enter your passkey to retrieve data:", type="password")

    if st.button("🔍 Retrieve Data"):
        if passkey in stored_data:
            try:
                decrypted_data = decrypt_data(stored_data[passkey]["encrypted_text"], passkey)
                st.write(f"🔓 Decrypted Data: {decrypted_data}")
            except Exception as e:
                failed_attempts += 1
                st.error("❌ Incorrect passkey. Try again.")
                st.write(f"❗ Failed attempts: {failed_attempts}")
        else:
            failed_attempts += 1
            st.error("❌ Data not found for this passkey.")
            st.write(f"❗ Failed attempts: {failed_attempts}")
        
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            st.warning("⚠️ Too many failed attempts! Redirecting to login... 🔑")
            time.sleep(2)
            login_page()

# Login Page - Used for reauthorization after failed attempts
def login_page():
    global failed_attempts
    st.title("🔑 Login Page")
    username = st.text_input("Enter Username:")
    password = st.text_input("Enter Password:", type="password")

    if st.button("🔐 Login"):
        # A simple check (you can replace it with a real authentication system)
        if username == "admin" and password == "admin":
            failed_attempts = 0
            st.success("✅ Login successful! Redirecting to home page... 🔄")
            time.sleep(2)
            home_page()
        else:
            st.error("❌ Invalid credentials. Try again.")

if __name__ == "__main__":
    home_page()

