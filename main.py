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


def toggle_secret_key_visibility():
    if entry_secret_key.cget("show") == "":
        entry_secret_key.config(show="*")
    else:
        entry_secret_key.config(show="")
        
def process_file():
    file_path = entry_file_path.get()
    key = entry_secret_key.get().encode()  # Convert key to bytes
    if not file_path or not key:
        messagebox.showerror("Error", "Please select a file and enter a secret key.")
        return
    
    # Determine action based on file extension
    if file_path.endswith('.enc'):
        try:
            new_file_path = decrypt_file(file_path, key)
            # messagebox.showinfo("Success", "File decrypted successfully.")
            entry_file_path.delete(0, tk.END)  
            entry_file_path.insert(0, new_file_path)  
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt the file.")
            print(e)
    else:
        try:
            new_file_path = encrypt_file(file_path, key)
            # messagebox.showinfo("Success", "File encrypted successfully.")
            entry_file_path.delete(0, tk.END)  
            entry_file_path.insert(0, new_file_path)  
        except Exception as e:
            messagebox.showerror("Error", "Failed to encrypt the file.")
            print(e)

# Modify the generate_key function to display the key in the entry widget
def generate_and_fill():
    key = generate_key()
    entry_secret_key.delete(0, tk.END)  # Clear existing entry
    entry_secret_key.insert(0, key.decode())  # Fernet keys are bytes; decode to string
    # messagebox.showinfo("Key Generated", "A new secret key has been generated and filled in.")

# Setting up the GUI with adjusted layout
root = tk.Tk()
root.title("EnDecryptor")

root.geometry("760x130")

root.columnconfigure(0, weight=1)

# File selection frame
frame_file = tk.Frame(root)
frame_file.pack(fill=tk.X, padx=10, pady=5, anchor='w')

lbl_select_file = tk.Label(frame_file, text="Select File:")
lbl_select_file.pack(side=tk.LEFT, anchor='w')

entry_file_path = tk.Entry(frame_file)
entry_file_path.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

btn_browse = tk.Button(frame_file, text="Browse", command=select_file)
btn_browse.pack(side=tk.LEFT, anchor='w')

# Secret key frame
frame_key = tk.Frame(root)
frame_key.pack(fill=tk.X, padx=10, pady=5, anchor='w')

lbl_secret_key = tk.Label(frame_key, text="Secret Key:")
lbl_secret_key.pack(side=tk.LEFT, anchor='w')

entry_secret_key = tk.Entry(frame_key, show="*")
entry_secret_key.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

btn_toggle_key = tk.Button(frame_key, text="Show/Hide Key", command=toggle_secret_key_visibility)
btn_toggle_key.pack(side=tk.LEFT, anchor='w')

btn_generate_key = tk.Button(frame_key, text="Generate New Key", command=generate_and_fill)
btn_generate_key.pack(side=tk.LEFT, anchor='w')

# Actions frame
frame_actions = tk.Frame(root)
frame_actions.pack(fill=tk.X, padx=10, pady=10)

btn_process = tk.Button(frame_actions, text="Encrypt/Decrypt", command=process_file)  # Assume process_file decides whether to encrypt or decrypt
btn_process.pack(side=tk.BOTTOM)

root.mainloop()