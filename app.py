import streamlit as st
from cryptography.fernet import Fernet

# Title
st.title("🔒 Secure Data Encryption & Decryption")

# Sidebar
st.sidebar.title("Options")
operation = st.sidebar.selectbox("Choose an operation:", ["Encrypt", "Decrypt"])

# Generate key
def generate_key():
    return Fernet.generate_key()

# Encrypt message
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

# Decrypt message
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# Main logic
if operation == "Encrypt":
    st.subheader("🔐 Encrypt your text")
    message = st.text_area("Enter the message you want to encrypt:")
    if st.button("Encrypt"):
        if message:
            key = generate_key()
            encrypted_message = encrypt_message(message, key)
            st.success("Encryption Successful!")
            st.text_area("🔑 Your Secret Key (save it safely):", key.decode())
            st.text_area("🧩 Encrypted Message:", encrypted_message.decode())
        else:
            st.warning("Please enter a message to encrypt.")

elif operation == "Decrypt":
    st.subheader("🛡️ Decrypt your text")
    encrypted_message = st.text_area("Paste the encrypted message:")
    key = st.text_input("Enter your secret key:")
    if st.button("Decrypt"):
        try:
            if encrypted_message and key:
                decrypted_message = decrypt_message(encrypted_message.encode(), key.encode())
                st.success("Decryption Successful!")
                st.text_area("✅ Decrypted Message:", decrypted_message)
            else:
                st.warning("Please provide both encrypted message and key.")
        except Exception as e:
            st.error(f"Decryption failed: {e}")
