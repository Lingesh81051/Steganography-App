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

# -------------------------------
# Global Constants & Variables
# -------------------------------
HISTORY_FILE = "history.csv"
GENERIC_ERROR = ("Error: Embedded data is corrupt OR invalid password has been provided OR "
                 "the wrong algorithm for the given file.")

# (The following globals will be assigned in the GUI‐builder functions)
# Encryption mode widgets:
entry_image_path_encode = None
text_message_encode = None
entry_text_file = None
password_var_encode = None
password_strength_var = None
entry_password_encode = None
encryption_algo = None
message_input_option = None
# Decryption mode widgets:
entry_image_path_decode = None
entry_password_decode = None
text_message_decode = None
encryption_algo_decode = None

# -------------------------------
# CreateToolTip Class
# -------------------------------
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

# -------------------------------
# Operation History Functions
# -------------------------------
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

def log_operation(operation, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (operation, details, timestamp)
    operation_history.append(entry)
    with open(HISTORY_FILE, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(entry)

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

# -------------------------------
# AES Encryption/Decryption Helpers
# -------------------------------
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

# -------------------------------
# Utility Functions
# -------------------------------
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
    # Clear encryption widgets if they exist
    if entry_image_path_encode is not None:
        entry_image_path_encode.delete(0, tk.END)
    if message_input_option is not None:
        if message_input_option.get() == "type" and text_message_encode is not None:
            text_message_encode.config(state="normal")
            text_message_encode.delete("1.0", tk.END)
        elif entry_text_file is not None:
            entry_text_file.delete(0, tk.END)
    if password_var_encode is not None:
        password_var_encode.set("")
    # Clear decryption widgets if they exist
    if entry_image_path_decode is not None:
        entry_image_path_decode.delete(0, tk.END)
    if entry_password_decode is not None:
        entry_password_decode.delete(0, tk.END)
    if text_message_decode is not None:
        text_message_decode.config(state="normal")
        text_message_decode.delete("1.0", tk.END)
    
def show_about():
    messagebox.showinfo("About Steganography App",
                        "Steganography App v3.0\n\n"
                        "This tool lets you hide secret messages within images using encryption methods such as AES-128, AES-256, SHA-256, and MD5.\n\n"
                        "Developed by LSquare.\n\nFor help, contact lingeshrm2002@gmail.com.")

def update_encode_password_visibility():
    if entry_password_encode is not None:
        if chk_show_password_encode_var.get():
            entry_password_encode.config(show="")
        else:
            entry_password_encode.config(show="*")

def update_decode_password_visibility():
    if entry_password_decode is not None:
        if chk_show_password_decode_var.get():
            entry_password_decode.config(show="")
        else:
            entry_password_decode.config(show="*")

def check_password_strength(event=None):
    pwd = password_var_encode.get() if password_var_encode is not None else ""
    if len(pwd) < 6:
        strength = "Weak"
    elif len(pwd) < 10:
        strength = "Moderate"
    else:
        strength = "Strong"
    password_strength_var.set(strength)

def update_message_input():
    if message_input_option.get() == "type":
        type_frame.grid()
        file_frame.grid_remove()
    else:
        file_frame.grid()
        type_frame.grid_remove()

# -------------------------------
# GUI Builder Functions
# -------------------------------
# These two functions build the GUI for encryption and decryption modes separately.
# They accept a processing function (passed from Encrypt.py or Decrypt.py) that is bound to the action button.

def run_encrypt_gui(process_function):
    global root, entry_image_path_encode, text_message_encode, entry_text_file
    global password_var_encode, password_strength_var, entry_password_encode, encryption_algo
    global message_input_option, type_frame, file_frame, chk_show_password_encode_var

    root = tk.Tk()
    root.title("Steganography App - Hide Data")
    root.geometry("517x650")
    root.configure(bg="#f4f4f4")
    
    # Style Setup
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TLabel", background="#f4f4f4", font=("Helvetica", 11))
    style.configure("TButton", font=("Helvetica", 10), padding=3)
    style.configure("TEntry", padding=3)
    style.configure("TCombobox", 
                    padding=3, 
                    fieldbackground="#d3d3d3", 
                    background="#d3d3d3", 
                    borderwidth=1, 
                    relief="solid",
                    foreground="black")
    # Update the mapping to remove grey highlight and set selected text to black:
    style.map("TCombobox", 
              fieldbackground=[("readonly", "white")],
              foreground=[("readonly", "black")],
              selectbackground=[("readonly", "white")],
              selectforeground=[("readonly", "black")])
    
    # Configure label frame title with larger bold font and remove any border highlight
    style.configure("TLabelframe", background="#f4f4f4", padding=10)
    style.configure("TLabelframe.Label", font=("Helvetica", 14, "bold"), background="#f4f4f4", borderwidth=0)
    # Remove grey highlight for radio buttons and checkbuttons
    style.configure("TRadiobutton", background="#f4f4f4", highlightthickness=0, borderwidth=0)
    style.configure("TCheckbutton", background="#f4f4f4", highlightthickness=0, borderwidth=0)
    
    # Variables for encryption mode
    password_var_encode = tk.StringVar()
    password_var_encode.trace("w", lambda *args: check_password_strength())
    password_strength_var = tk.StringVar()
    chk_show_password_encode_var = tk.BooleanVar(value=False)
    
    # Build Encryption Screen
    encode_frame = tk.Frame(root, bg="#f4f4f4")
    encode_frame.grid(row=0, column=0, sticky="nsew")
    
    encode_group = ttk.LabelFrame(encode_frame, text="Hide Data", padding=15)
    encode_group.pack(fill="both", expand=True, padx=20, pady=20)
    encode_group.columnconfigure(0, weight=1)
    
    ttk.Label(encode_group, text="Select Image:").grid(row=0, column=0, sticky="w", padx=10, pady=(10,5))
    entry_image_path_encode = ttk.Entry(encode_group, width=50)
    entry_image_path_encode.grid(row=1, column=0, sticky="ew", padx=(10,2), pady=(5,10))
    ttk.Button(encode_group, text="Browse", command=lambda: select_image(entry_image_path_encode), takefocus=0)\
        .grid(row=1, column=1, sticky="w", padx=(2,10), pady=(5,10))
    CreateToolTip(entry_image_path_encode, "Enter or browse for the cover image file.")
    
    ttk.Label(encode_group, text="Select Message File:").grid(row=2, column=0, sticky="w", padx=10, pady=(10,5))
    message_radio_frame = tk.Frame(encode_group, bg="#f4f4f4")
    message_radio_frame.grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=(0,10))
    message_input_option = tk.StringVar(value="type")
    ttk.Radiobutton(message_radio_frame, text="Type Message", variable=message_input_option,
                    value="type", command=update_message_input, takefocus=0).pack(side="left", padx=10)
    ttk.Radiobutton(message_radio_frame, text="Select Text File", variable=message_input_option,
                    value="file", command=update_message_input, takefocus=0).pack(side="left", padx=10)
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
    ttk.Button(file_frame, text="Browse Text File", command=browse_text_file, takefocus=0).pack(side="left")
    file_frame.grid_remove()
    CreateToolTip(file_frame, "Browse for a text file containing your message.")
    
    ttk.Label(encode_group, text="Select Encryption Algorithm:").grid(row=5, column=0, sticky="w", padx=10, pady=(10,5))
    encryption_algo = ttk.Combobox(encode_group,
                                   values=["None (Basic Encoding)", "AES-128", "AES-256", "SHA-256", "MD5"],
                                   width=47, state="readonly")
    encryption_algo.grid(row=6, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
    encryption_algo.set("None (Basic Encoding)")
    CreateToolTip(encryption_algo, "Select the encryption method to use.")
    
    ttk.Label(encode_group, text="Enter Password:").grid(row=7, column=0, sticky="w", padx=10, pady=(10,5))
    entry_password_encode = ttk.Entry(encode_group, textvariable=password_var_encode, show="*", width=50, font=("Helvetica", 10))
    entry_password_encode.grid(row=8, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
    CreateToolTip(entry_password_encode, "Enter a password to secure the data.")
    
    chk_show_password_encode = ttk.Checkbutton(encode_group, text="Show Password", variable=chk_show_password_encode_var,
                                               command=update_encode_password_visibility, takefocus=0)
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
    ttk.Button(buttons_frame, text="Encode", command=process_function, width=10).pack(side="left", padx=5)
    
    # Menu Bar (only "Hide Data" shown)
    menubar = tk.Menu(root)
    files_menu = tk.Menu(menubar, tearoff=0)
    files_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="Files", menu=files_menu)
    menubar.add_command(label="Hide Data", command=lambda: encode_frame.tkraise())
    menubar.add_command(label="History", command=show_history)
    help_menu = tk.Menu(menubar, tearoff=0)
    help_menu.add_command(label="About", command=show_about)
    menubar.add_cascade(label="Help", menu=help_menu)
    root.config(menu=menubar)
    
    root.mainloop()

def run_decrypt_gui(process_function):
    global root, entry_image_path_decode, entry_password_decode, text_message_decode
    global encryption_algo_decode, chk_show_password_decode_var

    root = tk.Tk()
    root.title("Steganography App - Reveal Data")
    root.geometry("517x650")
    root.configure(bg="#f4f4f4")
    
    # Style Setup
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TLabel", background="#f4f4f4", font=("Helvetica", 11))
    style.configure("TButton", font=("Helvetica", 10), padding=3)
    style.configure("TEntry", padding=3)
    style.configure("TCombobox", 
                    padding=3, 
                    fieldbackground="#d3d3d3", 
                    background="#d3d3d3", 
                    borderwidth=1, 
                    relief="solid",
                    foreground="black")
    # Update the mapping to remove grey highlight and set text to black
    style.map("TCombobox", 
              fieldbackground=[("readonly", "white")],
              foreground=[("readonly", "black")],
              selectbackground=[("readonly", "white")],
              selectforeground=[("readonly", "black")])
    
    style.configure("TLabelframe", background="#f4f4f4", padding=10)
    style.configure("TLabelframe.Label", font=("Helvetica", 14, "bold"), background="#f4f4f4", borderwidth=0)
    style.configure("TRadiobutton", background="#f4f4f4", highlightthickness=0, borderwidth=0)
    style.configure("TCheckbutton", background="#f4f4f4", highlightthickness=0, borderwidth=0)
    
    # Variable for decryption mode
    chk_show_password_decode_var = tk.BooleanVar(value=False)
    
    # Build Decryption Screen
    decode_frame = tk.Frame(root, bg="#f4f4f4")
    decode_frame.grid(row=0, column=0, sticky="nsew")
    
    decode_group = ttk.LabelFrame(decode_frame, text="Reveal Data", padding=15)
    decode_group.pack(fill="both", expand=True, padx=20, pady=20)
    decode_group.columnconfigure(0, weight=1)
    
    ttk.Label(decode_group, text="Select Image:").grid(row=0, column=0, sticky="w", padx=10, pady=(10,5))
    entry_image_path_decode = ttk.Entry(decode_group, width=50)
    entry_image_path_decode.grid(row=1, column=0, sticky="ew", padx=(10,2), pady=(5,10))
    ttk.Button(decode_group, text="Browse", command=lambda: select_image(entry_image_path_decode), takefocus=0)\
        .grid(row=1, column=1, sticky="w", padx=(2,10), pady=(5,10))
    CreateToolTip(entry_image_path_decode, "Enter the path of the image to decode.")
    
    ttk.Label(decode_group, text="Enter Password:").grid(row=2, column=0, sticky="w", padx=10, pady=(10,5))
    entry_password_decode = ttk.Entry(decode_group, show="*", width=50, font=("Helvetica", 10))
    entry_password_decode.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
    CreateToolTip(entry_password_decode, "Enter the password used during encoding.")
    chk_show_password_decode = ttk.Checkbutton(decode_group, text="Show Password", variable=chk_show_password_decode_var,
                                               command=update_decode_password_visibility, takefocus=0)
    chk_show_password_decode.grid(row=4, column=0, sticky="w", padx=10, pady=(0,10))
    CreateToolTip(chk_show_password_decode, "Check to reveal the password.")
    
    ttk.Label(decode_group, text="Select Encryption Algorithm:").grid(row=5, column=0, sticky="w", padx=10, pady=(10,5))
    encryption_algo_decode = ttk.Combobox(decode_group,
                                          values=["None (Basic Encoding)", "AES-128", "AES-256", "SHA-256", "MD5"],
                                          width=47, state="readonly")
    encryption_algo_decode.grid(row=6, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
    encryption_algo_decode.current(0)
    CreateToolTip(encryption_algo_decode, "Select the algorithm used to encode the message.")
    
    ttk.Button(decode_group, text="Decode", command=process_function, width=10, takefocus=0)\
        .grid(row=7, column=1, sticky="e", padx=(0,10), pady=10)
    
    ttk.Label(decode_group, text="Decoded Message:").grid(row=8, column=0, sticky="w", padx=10, pady=(10,5))
    text_message_decode = tk.Text(decode_group, height=5, width=50, font=("Helvetica", 10))
    text_message_decode.grid(row=9, column=0, columnspan=2, sticky="ew", padx=10, pady=(5,10))
    text_message_decode.config(state="disabled")
    CreateToolTip(text_message_decode, "The decoded message will appear here.")
    
    decode_buttons_frame = tk.Frame(decode_group, bg="#f4f4f4")
    decode_buttons_frame.grid(row=10, column=0, columnspan=2, sticky="e", pady=20, padx=(0,10))
    ttk.Button(decode_buttons_frame, text="Clear", command=clear_fields, width=10, takefocus=0).pack(side="left", padx=5)
    ttk.Button(decode_buttons_frame, text="Decode", command=process_function, width=10, takefocus=0).pack(side="left", padx=5)
    
    # Menu Bar (only "Reveal Data" shown)
    menubar = tk.Menu(root)
    files_menu = tk.Menu(menubar, tearoff=0)
    files_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="Files", menu=files_menu)
    menubar.add_command(label="Reveal Data", command=lambda: decode_frame.tkraise())
    menubar.add_command(label="History", command=show_history)
    help_menu = tk.Menu(menubar, tearoff=0)
    help_menu.add_command(label="About", command=show_about)
    menubar.add_cascade(label="Help", menu=help_menu)
    root.config(menu=menubar)
    
    root.mainloop()

# -------------------------------
# Main Entry Point for Stegano.py
# -------------------------------
if __name__ == "__main__":
    print("This is a module. Run Encrypt.py or Decrypt.py to open the respective GUI.")
