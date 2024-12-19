import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

# Function for Encryption
def encrypt_file(file_data, key):
    key = key.encode('utf-8')
    iv = get_random_bytes(16)  # Initialization Vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad data to be multiple of 16 bytes
    padded_data = file_data + b' ' * (16 - len(file_data) % 16)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

# Function for Decryption
def decrypt_file(file_data, key):
    key = key.encode('utf-8')
    iv = file_data[:16]  # Extract IV from the file data
    encrypted_data = file_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.rstrip(b' ')  # Remove padding

# Streamlit UI
st.title("🔒 AES-128 File Encryption & Decryption Tool")

# Tabs for Encryption and Decryption
tab1, tab2 = st.tabs(["Encrypt File", "Decrypt File"])

with tab1:
    st.header("Encrypt File")
    enc_file = st.file_uploader("Upload file to encrypt (PDF, Word, PNG, JPG, TIFF)", type=["pdf", "docx", "png", "jpg", "tiff"])
    enc_key = st.text_input("Enter a 16-character key:", type="password")
    
    if st.button("Encrypt"):
        if enc_file and len(enc_key) == 16:
            try:
                file_data = enc_file.read()
                encrypted_data = encrypt_file(file_data, enc_key)
                st.success("File encrypted successfully!")
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name=f"{enc_file.name}.enc",
                    mime="application/octet-stream"
                )
            except Exception as e:
                st.error(f"An error occurred during encryption: {e}")
        else:
            st.error("Please upload a file and enter a 16-character key.")

with tab2:
    st.header("Decrypt File")
    dec_file = st.file_uploader("Upload encrypted file (.enc)", type=["enc"])
    dec_key = st.text_input("Enter the decryption key:", type="password")
    
    if st.button("Decrypt"):
        if dec_file and len(dec_key) == 16:
            try:
                file_data = dec_file.read()
                decrypted_data = decrypt_file(file_data, dec_key)
                st.success("File decrypted successfully!")
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name=f"decrypted_{os.path.splitext(dec_file.name)[0]}",
                    mime="application/octet-stream"
                )
            except ValueError:
                st.error("Invalid key or corrupted file.")
            except Exception as e:
                st.error(f"An error occurred during decryption: {e}")
        else:
            st.error("Please upload a file and enter a 16-character key.")
