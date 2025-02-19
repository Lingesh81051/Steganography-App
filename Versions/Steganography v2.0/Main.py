# Main.py
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
import stepic
import hashlib
from Crypto.Cipher import AES
import base64
import datetime
import os
import csv

import Encrypt
import Decrypt

# File to store operation history
HISTORY_FILE = "history.csv"

# Generic error message for decryption failures
GENERIC_ERROR = "Error: Embedded data is corrupt OR invalid password has been provided OR the wrong algorithm for the given file."

# ============================
# CreateToolTip Class (for contextual tooltips)
# ============================
class CreateToolTip(object):
    def __init__(self, widget, text='widget info'):
        self.waittime = 500
        self.wraplength = 180
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave)
        self.id = None
        self.tw = None

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.waittime, self.showtip)

    def unschedule(self):
        id_ = self.id
        self.id = None
        if id_:
            self.widget.after_cancel(id_)

    def showtip(self, event=None):
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 20
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(self.tw, text=self.text, justify='left',
                         background="#ffffe0", relief='solid', borderwidth=1,
                         wraplength=self.wraplength, font=("Helvetica", 10))
        label.pack(ipadx=1)

    def hidetip(self):
        if self.tw:
            self.tw.destroy()
        self.tw = None

# ============================
# Global Defaults and Operation History
# ============================
default_algorithm = "None (Basic Encoding)"
operation_history = []  # List of tuples: (Operation, Details, Timestamp)

def load_history():
    global operation_history
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            operation_history = [tuple(row) for row in reader]
    else:
        operation_history = []

load_history()

# ============================
# AES Encryption/Decryption Functions
# ============================
def pad(text):
    padding_length = 16 - len(text) % 16
    return text + chr(padding_length) * padding_length

def unpad(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

def aes_encrypt(message, password):
    key = hashlib.sha256(password.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message)
    encrypted = cipher.encrypt(padded_message.encode())
    return base64.b64encode(encrypted).decode()

def aes_decrypt(encrypted_message, password):
    key = hashlib.sha256(password.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message)).decode()
    return unpad(decrypted)

def aes256_encrypt(message, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message)
    encrypted = cipher.encrypt(padded_message.encode())
    return base64.b64encode(encrypted).decode()

def aes256_decrypt(encrypted_message, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message)).decode()
    return unpad(decrypted)

# ============================
# Encryption/Decryption Selection Functions
# ============================
def encrypt_message(message, password, algorithm):
    if algorithm == "SHA-256":
        return "SHA256::" + message
    elif algorithm == "MD5":
        return "MD5::" + message
    elif algorithm == "AES-128":
        return "AES128::" + aes_encrypt(message, password)
    elif algorithm == "AES-256":
        return "AES256::" + aes256_encrypt(message, password)
    return "NONE::" + message

def decrypt_message(encrypted_message, password, algorithm):
    try:
        if algorithm == "AES-128":
            prefix = "AES128::"
            if not encrypted_message.startswith(prefix):
                return GENERIC_ERROR
            return aes_decrypt(encrypted_message[len(prefix):], password)
        elif algorithm == "AES-256":
            prefix = "AES256::"
            if not encrypted_message.startswith(prefix):
                return GENERIC_ERROR
            return aes256_decrypt(encrypted_message[len(prefix):], password)
        elif algorithm == "SHA-256":
            prefix = "SHA256::"
            if not encrypted_message.startswith(prefix):
                return GENERIC_ERROR
            return encrypted_message[len(prefix):]
        elif algorithm == "MD5":
            prefix = "MD5::"
            if not encrypted_message.startswith(prefix):
                return GENERIC_ERROR
            return encrypted_message[len(prefix):]
        elif algorithm == "None (Basic Encoding)":
            prefix = "NONE::"
            if not encrypted_message.startswith(prefix):
                return GENERIC_ERROR
            return encrypted_message[len(prefix):]
    except Exception:
        return GENERIC_ERROR
    return encrypted_message

# ============================
# Logging Function (with persistence)
# ============================
def log_operation(operation, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (operation, details, timestamp)
    operation_history.append(entry)
    with open(HISTORY_FILE, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(entry)

# ============================
# Utility Functions
# ============================
def select_image(entry_field):
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if file_path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, file_path)

def browse_text_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        entry_text_file.delete(0, tk.END)
        entry_text_file.insert(0, file_path)

def clear_fields():
    entry_image_path_encode.delete(0, tk.END)
    if message_input_option.get() == "type":
        text_message_encode.config(state="normal")
        text_message_encode.delete("1.0", tk.END)
    else:
        entry_text_file.delete(0, tk.END)
    password_var_encode.set("")
    entry_image_path_decode.delete(0, tk.END)
    entry_password_decode.delete(0, tk.END)
    text_message_decode.config(state="normal")
    text_message_decode.delete("1.0", tk.END)
    password_strength_var.set("")

def switch_frame(frame):
    frame.tkraise()

def show_about():
    messagebox.showinfo("About Steganography App",
                        "Steganography App v2.0\n\n"
                        "This tool lets you hide secret messages within images using encryption methods such as AES-128, AES-256, SHA-256, and MD5.\n\n"
                        "Developed by LSquare.\n\nFor help, contact lingeshrm2002@gmail.com.")

def show_help():
    messagebox.showinfo("Help", "Hover over controls for tips.")

# ============================
# Password Toggle Functions via Checkbutton
# ============================
def update_encode_password_visibility():
    if show_password_var_encode.get():
        entry_password_encode.config(show="")
    else:
        entry_password_encode.config(show="*")

def update_decode_password_visibility():
    if show_password_var_decode.get():
        entry_password_decode.config(show="")
    else:
        entry_password_decode.config(show="*")

# ============================
# Password Strength Checker
# ============================
def check_password_strength(event=None):
    pwd = password_var_encode.get()
    if len(pwd) < 6:
        strength = "Weak"
    elif len(pwd) < 10:
        strength = "Moderate"
    else:
        strength = "Strong"
    password_strength_var.set(strength)

# ============================
# Update Message Input Widgets
# ============================
def update_message_input():
    if message_input_option.get() == "type":
        type_frame.grid()
        file_frame.grid_remove()
    else:
        file_frame.grid()
        type_frame.grid_remove()

# ============================
# Operation History Window (Styled Table)
# ============================
def show_history():
    hist_win = tk.Toplevel(root)
    hist_win.title("Operation History")
    hist_win.geometry("600x300")
    hist_win.configure(bg="#f4f4f4")
    
    style_hist = ttk.Style(hist_win)
    style_hist.configure("History.Treeview", highlightthickness=0, bd=0, font=('Helvetica', 10))
    style_hist.configure("History.Treeview.Heading", font=('Helvetica', 11, 'bold'))
    style_hist.layout("History.Treeview", [('History.Treeview.treearea', {'sticky': 'nswe'})])
    
    tree = ttk.Treeview(hist_win, columns=("Operation", "Details", "Timestamp"), show="headings", style="History.Treeview")
    tree.heading("Operation", text="Operation")
    tree.heading("Details", text="Details")
    tree.heading("Timestamp", text="Timestamp")
    
    tree.column("Operation", width=120, anchor="center")
    tree.column("Details", width=300, anchor="center")
    tree.column("Timestamp", width=150, anchor="center")
    
    tree.tag_configure('oddrow', background="#f9f9f9")
    tree.tag_configure('evenrow', background="#e0e0e0")
    
    scrollbar = ttk.Scrollbar(hist_win, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    if not operation_history:
        tree.insert("", "end", values=("No operations logged yet.", "", ""))
    else:
        for idx, (op, details, ts) in enumerate(operation_history):
            tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
            tree.insert("", "end", values=(op, details, ts), tags=(tag,))

# ============================
# Begin UI Setup
# Create the root window
# ============================
root = tk.Tk()
root.title("Steganography App")
root.geometry("517x650")
root.configure(bg="#f4f4f4")

# ============================
# Style and Frame Setup (Provided Snippet)
# ============================
style = ttk.Style(root)
style.theme_use("clam")
style.configure("TLabel", background="#f4f4f4", font=("Helvetica", 11))
style.configure("Header.TLabel", background="#f4f4f4", font=("Helvetica", 18, "bold"))
style.configure("TButton", font=("Helvetica", 10), padding=3)
style.configure("TEntry", padding=3)
style.configure("TCombobox", 
                padding=3, 
                fieldbackground="#d3d3d3", 
                background="#d3d3d3", 
                borderwidth=1, 
                relief="solid",
                foreground="black")
style.map("TCombobox", 
          fieldbackground=[("readonly", "#FFFFFF")],
          foreground=[("readonly", "black")],
          selectbackground=[("readonly", "#")],
          selectforeground=[("readonly", "#")])
style.configure("TLabelframe", background="#f4f4f4", font=("Helvetica", 12, "bold"), foreground="#333")
style.configure("TLabelframe.Label", background="#f4f4f4", font=("Helvetica", 12, "bold"))
style.configure("Flat.TButton", relief="flat", borderwidth=0)
style.configure("TRadiobutton", background="#f4f4f4")
style.configure("TCheckbutton", background="#f4f4f4")

password_var_encode = tk.StringVar()
password_var_encode.trace("w", lambda *args: check_password_strength())
password_strength_var = tk.StringVar()

# ============================
# Create frames for the two screens.
# ============================
encode_frame = tk.Frame(root, bg="#f4f4f4")
decode_frame = tk.Frame(root, bg="#f4f4f4")
for frame in (encode_frame, decode_frame):
    frame.grid(row=0, column=0, sticky="nsew")

# ============================
# Encode Screen (Hide Data)
# ============================
encode_group = ttk.LabelFrame(encode_frame, text="Hide Data", padding=15)
encode_group.pack(fill="both", expand=True, padx=20, pady=20)
encode_group.columnconfigure(0, weight=1)

ttk.Label(encode_group, text="Select Image:").grid(row=0, column=0, sticky="w", padx=10, pady=(10,5))
entry_image_path_encode = ttk.Entry(encode_group, width=50)
entry_image_path_encode.grid(row=1, column=0, sticky="ew", padx=(10,2), pady=(5,10))
ttk.Button(encode_group, text="Browse", command=lambda: select_image(entry_image_path_encode))\
    .grid(row=1, column=1, sticky="w", padx=(2,10), pady=(5,10))
CreateToolTip(entry_image_path_encode, "Enter or browse for the cover image file.")

ttk.Label(encode_group, text="Select Message File:").grid(row=2, column=0, sticky="w", padx=10, pady=(10,5))
message_radio_frame = tk.Frame(encode_group, bg="#f4f4f4")
message_radio_frame.grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=(0,10))
message_input_option = tk.StringVar(value="type")
ttk.Radiobutton(message_radio_frame, text="Type Message", variable=message_input_option,
                value="type", command=update_message_input).pack(side="left", padx=10)
ttk.Radiobutton(message_radio_frame, text="Select Text File", variable=message_input_option,
                value="file", command=update_message_input).pack(side="left", padx=10)
CreateToolTip(message_radio_frame, "Choose to type your message or select a text file.")

message_input_frame = tk.Frame(encode_group, bg="#f4f4f4")
message_input_frame.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=(0,10))
type_frame = tk.Frame(message_input_frame, bg="#f4f4f4")
type_frame.grid(row=0, column=0, sticky="nsew")
text_message_encode = tk.Text(type_frame, height=5, width=60, font=("Helvetica", 10))
text_message_encode.pack(fill="both", expand=True)
CreateToolTip(text_message_encode, "Type your secret message here.")
file_frame = tk.Frame(message_input_frame, bg="#f4f4f4")
file_frame.grid(row=0, column=0, sticky="nsew")
entry_text_file = ttk.Entry(file_frame, width=50)
entry_text_file.pack(side="left", fill="x", expand=True, padx=(0,5))
ttk.Button(file_frame, text="Browse Text File", command=browse_text_file).pack(side="left")
file_frame.grid_remove()
CreateToolTip(file_frame, "Browse for a text file containing your message.")

ttk.Label(encode_group, text="Select Encryption Algorithm:").grid(row=5, column=0, sticky="w", padx=10, pady=(10,5))
encryption_algo = ttk.Combobox(encode_group,
                               values=["None (Basic Encoding)", "AES-128", "AES-256", "SHA-256", "MD5"],
                               width=47, state="readonly")
encryption_algo.grid(row=6, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
encryption_algo.set(default_algorithm)
CreateToolTip(encryption_algo, "Select the encryption method to use.")

ttk.Label(encode_group, text="Enter Password:").grid(row=7, column=0, sticky="w", padx=10, pady=(10,5))
password_var_encode.set("")
entry_password_encode = ttk.Entry(encode_group, textvariable=password_var_encode, show="*", width=50, font=("Helvetica", 10))
entry_password_encode.grid(row=8, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
CreateToolTip(entry_password_encode, "Enter a password to secure the data.")

show_password_var_encode = tk.BooleanVar(value=False)
chk_show_password_encode = ttk.Checkbutton(encode_group, text="Show Password", variable=show_password_var_encode,
                                           command=update_encode_password_visibility)
chk_show_password_encode.grid(row=9, column=0, sticky="w", padx=10, pady=(0,10))
CreateToolTip(chk_show_password_encode, "Check to reveal the password.")

ttk.Label(encode_group, text="Password Strength:", font=("Helvetica", 10), background="#f4f4f4")\
    .grid(row=10, column=0, sticky="w", padx=10, pady=(10,5))
ttk.Label(encode_group, textvariable=password_strength_var, font=("Helvetica", 10, "italic"),
          background="#f4f4f4", foreground="#007700")\
    .grid(row=10, column=1, sticky="w", padx=(2,10), pady=(10,5))

buttons_frame = tk.Frame(encode_group, bg="#f4f4f4")
buttons_frame.grid(row=11, column=0, columnspan=2, sticky="e", pady=20, padx=(0,10))
ttk.Button(buttons_frame, text="Clear", command=clear_fields, width=10).pack(side="left", padx=5)
ttk.Button(buttons_frame, text="Encode", 
           command=lambda: Encrypt.encode_message(entry_image_path_encode, text_message_encode, entry_text_file, 
                                                    message_input_option, password_var_encode, encryption_algo, 
                                                    encrypt_message, log_operation, clear_fields),
           width=10).pack(side="left", padx=5)

# ============================
# Decode Screen (Reveal Data)
# ============================
decode_group = ttk.LabelFrame(decode_frame, text="Reveal Data", padding=15)
decode_group.pack(fill="both", expand=True, padx=20, pady=20)
decode_group.columnconfigure(0, weight=1)

ttk.Label(decode_group, text="Select Image:").grid(row=0, column=0, sticky="w", padx=10, pady=(10,5))
entry_image_path_decode = ttk.Entry(decode_group, width=50)
entry_image_path_decode.grid(row=1, column=0, sticky="ew", padx=(10,2), pady=(5,10))
ttk.Button(decode_group, text="Browse", command=lambda: select_image(entry_image_path_decode))\
    .grid(row=1, column=1, sticky="w", padx=(2,10), pady=(5,10))
CreateToolTip(entry_image_path_decode, "Enter the path of the image to decode.")

ttk.Label(decode_group, text="Enter Password:").grid(row=2, column=0, sticky="w", padx=10, pady=(10,5))
entry_password_decode = ttk.Entry(decode_group, show="*", width=50, font=("Helvetica", 10))
entry_password_decode.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
entry_password_decode.bind("<KeyRelease>", lambda e: None)
CreateToolTip(entry_password_decode, "Enter the password used during encoding.")
show_password_var_decode = tk.BooleanVar(value=False)
chk_show_password_decode = ttk.Checkbutton(decode_group, text="Show Password", variable=show_password_var_decode,
                                           command=update_decode_password_visibility)
chk_show_password_decode.grid(row=4, column=0, sticky="w", padx=10, pady=(0,10))
CreateToolTip(chk_show_password_decode, "Check to reveal the password.")

ttk.Label(decode_group, text="Select Encryption Algorithm:").grid(row=5, column=0, sticky="w", padx=10, pady=(10,5))
encryption_algo_decode = ttk.Combobox(decode_group,
                                      values=["None (Basic Encoding)", "AES-128", "AES-256", "SHA-256", "MD5"],
                                      width=47, state="readonly")
encryption_algo_decode.grid(row=6, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
encryption_algo_decode.current(0)
CreateToolTip(encryption_algo_decode, "Select the algorithm used to encode the message.")

ttk.Button(decode_group, text="Decode", 
           command=lambda: Decrypt.decode_message(entry_image_path_decode, entry_password_decode, 
                                                    encryption_algo_decode, text_message_decode, 
                                                    decrypt_message, log_operation, GENERIC_ERROR),
           width=10).grid(row=7, column=1, sticky="e", padx=(0,10), pady=10)

ttk.Label(decode_group, text="Decoded Message:").grid(row=8, column=0, sticky="w", padx=10, pady=(10,5))
text_message_decode = tk.Text(decode_group, height=5, width=50, font=("Helvetica", 10))
text_message_decode.grid(row=9, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
text_message_decode.config(state="disabled")
CreateToolTip(text_message_decode, "The decoded message will appear here.")

decode_buttons_frame = tk.Frame(decode_group, bg="#f4f4f4")
decode_buttons_frame.grid(row=10, column=0, columnspan=2, sticky="e", pady=20, padx=(0,10))
ttk.Button(decode_buttons_frame, text="Clear", command=clear_fields, width=10).pack(side="left", padx=5)
ttk.Button(decode_buttons_frame, text="Decode", 
           command=lambda: Decrypt.decode_message(entry_image_path_decode, entry_password_decode, 
                                                    encryption_algo_decode, text_message_decode, 
                                                    decrypt_message, log_operation, GENERIC_ERROR),
           width=10).pack(side="left", padx=5)

# ============================
# Menu Bar (Header) Setup
# ============================
menubar = tk.Menu(root)
files_menu = tk.Menu(menubar, tearoff=0)
files_menu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="Files", menu=files_menu)
menubar.add_command(label="Hide Data", command=lambda: switch_frame(encode_frame))
menubar.add_command(label="Reveal Data", command=lambda: switch_frame(decode_frame))
menubar.add_command(label="History", command=show_history)
help_menu = tk.Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menubar)

switch_frame(encode_frame)
root.mainloop()
