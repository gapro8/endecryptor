import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import zipfile
import os


# Backend logic
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key


def encrypt_file(file_path, key):
    zip_path = file_path + ".zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, os.path.basename(file_path))
    
    fernet = Fernet(key)
    with open(zip_path, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    
    with open(zip_path + ".enc", "wb") as file:
        file.write(encrypted_data)
    
    os.remove(zip_path)
    if os.path.exists(file_path): os.remove(file_path) 
    return zip_path + ".enc"

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    
    zip_path = file_path.replace(".enc", "")
    with open(zip_path, "wb") as file:
        file.write(decrypted_data)
    
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(os.path.dirname(zip_path))
    
    os.remove(zip_path)
    if os.path.exists(file_path): os.remove(file_path) 
    return zip_path.replace(".zip", "")



def select_file():
    file_path = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, file_path)

def encrypt_action():
    file_path = entry_file_path.get()
    key = entry_secret_key.get().encode()  # Ensure the key is in bytes
    if not file_path or not key  or file_path[-4:] == ".enc":
        messagebox.showerror("Error", "Please select a file and enter a secret key.")
        return

    new_file_path = encrypt_file(file_path, key)
    entry_file_path.delete(0, tk.END)  
    entry_file_path.insert(0, new_file_path) 
    messagebox.showinfo("Success", "File encrypted successfully.")

def decrypt_action():
    file_path = entry_file_path.get()
    key = entry_secret_key.get().encode()  # Ensure the key is in bytes
    if not file_path or not key or file_path[-4:] != ".enc":
        messagebox.showerror("Error", "Please select a file(.enc) and enter a secret key.")
        return

    new_file_path = decrypt_file(file_path, key)
    entry_file_path.delete(0, tk.END)  
    entry_file_path.insert(0, new_file_path)  
    messagebox.showinfo("Success", "File decrypted successfully.")

def toggle_secret_key_visibility():
    if entry_secret_key.cget("show") == "":
        entry_secret_key.config(show="*")
        btn_toggle_key.config(text="Show Key")
    else:
        entry_secret_key.config(show="")
        btn_toggle_key.config(text="Hide Key")

# Modify the generate_key function to display the key in the entry widget
def generate_and_fill():
    key = generate_key()
    entry_secret_key.delete(0, tk.END)  # Clear existing entry
    entry_secret_key.insert(0, key.decode())  # Fernet keys are bytes; decode to string
    # messagebox.showinfo("Key Generated", "A new secret key has been generated and filled in.")

# Setting up the GUI with adjusted layout
root = tk.Tk()
root.title("Encryptor-Decryptor Tool")

# File selection frame
frame_file = tk.Frame(root)
frame_file.pack(padx=10, pady=5)

lbl_select_file = tk.Label(frame_file, text="Select File:")
lbl_select_file.pack(side=tk.LEFT)

entry_file_path = tk.Entry(frame_file, width=60)
entry_file_path.pack(side=tk.LEFT, padx=5)

btn_browse = tk.Button(frame_file, text="Browse", command=select_file)
btn_browse.pack(side=tk.LEFT)

# Secret key frame
frame_key = tk.Frame(root)
frame_key.pack(padx=10, pady=5)

lbl_secret_key = tk.Label(frame_key, text="Secret Key:")
lbl_secret_key.pack(side=tk.LEFT)

entry_secret_key = tk.Entry(frame_key, width=50, show="*")  # Masks the input
entry_secret_key.pack(side=tk.LEFT, padx=5)

btn_generate_key = tk.Button(frame_key, text="Generate New Key", command=generate_and_fill)
btn_generate_key.pack(side=tk.LEFT)

btn_toggle_key = tk.Button(frame_key, text="Show Key", command=toggle_secret_key_visibility, width=10)
btn_toggle_key.pack(side=tk.LEFT)

# Actions frame
frame_actions = tk.Frame(root)
frame_actions.pack(padx=10, pady=10, fill=tk.X)

btn_encrypt = tk.Button(frame_actions, text="Encrypt", command=encrypt_action)
btn_encrypt.pack(side=tk.LEFT, expand=True, fill=tk.X)

btn_decrypt = tk.Button(frame_actions, text="Decrypt", command=decrypt_action)
btn_decrypt.pack(side=tk.LEFT, expand=True, fill=tk.X)

root.mainloop()
