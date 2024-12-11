import os
import hashlib
import random
import datetime
from tkinter import *
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import DES
import logging

# Setup logging
logging.basicConfig(filename='scan_log.txt', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# 目标哈希值的内容
content = "abc123fgedf"

# 生成文件并写入内容
file_path = 'D:\\EICAR\\13.txt'
with open(file_path, 'w') as file:
    file.write(content)

# 验证生成的文件的哈希值
def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()

md5_hash = calculate_md5(file_path)
#print(f"生成的文件的 MD5: {md5_hash}")

# Known malware hashes
KNOWN_MALWARE_HASHES = {
    'e99a18c428cb38d5f260853678922e03',
    'f50eb2e4f0a2d735af148f1c93d808de',
    'd41d8cd98f00b204e9800998ecf8427e',
    'a60999f6a010575cf676ce71cafd5fe8'
}

# Function to calculate MD5 hash of a file
def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Encrypt file function
def encrypt_file(file_path, key):
    iv = os.urandom(8)
    cipher = DES.new(key, DES.MODE_CFB, iv)
    with open(file_path, 'rb') as f:
        file_data = f.read()
    padded_data = file_data + b' ' * (8 - len(file_data) % 8)
    encrypted_data = iv + cipher.encrypt(padded_data)
    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)

# Decrypt file function
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    iv = encrypted_data[:8]
    encrypted_data = encrypted_data[8:]
    cipher = DES.new(key, DES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(encrypted_data).rstrip(b' ')
    with open(file_path[:-4], 'wb') as f:
        f.write(decrypted_data)

# Generate random key (8 bytes)
def generate_key():
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890', k=8)).encode('utf-8')

# Scan folder for files
def scan_folder(folder_path):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_md5 = calculate_md5(file_path)
            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if file_md5 in KNOWN_MALWARE_HASHES:
                tree.insert("", "end", text=file, values=(scan_time,), tags=('malware',))
                log_scan_event(file_path, scan_time, "Malware detected")
            else:
                tree.insert("", "end", text=file, values=(scan_time,))
                log_scan_event(file_path, scan_time, "Clean")

# Log scan event
def log_scan_event(file_path, scan_time, status):
    logging.info(f"Scanned file: {file_path} | Time: {scan_time} | Status: {status}")

# Delete selected file
def delete_file(file_path):
    os.remove(file_path)

# GUI setup
root = Tk()
root.title("Malware Scanner")
root.geometry("800x400")

frame = Frame(root)
frame.pack(pady=20)

tree = ttk.Treeview(frame, columns=("scan_time",))
tree.column("#0", width=300, minwidth=300)  # Ensure the file name column is wide enough
tree.heading("#0", text="File Name")
tree.column("scan_time", width=200, minwidth=200)
tree.heading("scan_time", text="Scan Time")
tree.tag_configure('malware', background='red')
tree.pack()

def select_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        scan_folder(folder_path)

def on_delete():
    selected_item = tree.selection()
    if selected_item:
        file_name = tree.item(selected_item, 'text')
        folder_path = filedialog.askdirectory()  # Get the folder path to scan
        if folder_path:
            file_path = os.path.join(folder_path, file_name)
            if messagebox.askyesno("Delete File", f"Do you want to delete {file_path}?"):
                try:
                    delete_file(file_path)
                    tree.delete(selected_item)
                    log_scan_event(file_path, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Deleted")
                except FileNotFoundError:
                    messagebox.showerror("Error", f"File {file_path} not found.")
                    log_scan_event(file_path, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "File not found")

btn_select_folder = Button(root, text="Select Folder", command=select_folder)
btn_select_folder.pack(pady=10)

btn_delete = Button(root, text="Delete File", command=on_delete)
btn_delete.pack(pady=10)

root.mainloop()
