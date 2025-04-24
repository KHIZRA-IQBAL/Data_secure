import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import time
import base64


stored_data = {}  
failed_attempts = 0 
MAX_FAILED_ATTEMPTS = 3  


def generate_key():
    return Fernet.generate_key()


def encrypt_data(data, passkey):
    key = hashlib.sha256(passkey.encode()).digest()  
    fernet_key = base64.urlsafe_b64encode(key)  
    fernet = Fernet(fernet_key)  
    encrypted = fernet.encrypt(data.encode())
    return encrypted

def decrypt_data(encrypted_data, passkey):
    key = hashlib.sha256(passkey.encode()).digest()  
    fernet_key = base64.urlsafe_b64encode(key)  
    fernet = Fernet(fernet_key)  
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted


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

def login_page():
    global failed_attempts
    st.title("🔑 Login Page")
    username = st.text_input("Enter Username:")
    password = st.text_input("Enter Password:", type="password")

    if st.button("🔐 Login"):
        if username == "admin" and password == "admin":
            failed_attempts = 0
            st.success("✅ Login successful! Redirecting to home page... 🔄")
            time.sleep(2)
            home_page()
        else:
            st.error("❌ Invalid credentials. Try again.")

if __name__ == "__main__":
    home_page()

