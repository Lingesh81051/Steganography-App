# Encrypt.py
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import stepic

def encode_message(entry_image_path, text_message_widget, entry_text_file, message_input_option, 
                   password_var, encryption_algo, encrypt_message, log_operation, clear_fields):
    image_path = entry_image_path.get()
    password = password_var.get()
    algorithm = encryption_algo.get()

    if not image_path or not password:
        messagebox.showerror("Error", "Please select an image and enter a password")
        return

    if message_input_option.get() == "type":
        message = text_message_widget.get("1.0", tk.END).strip()
    else:
        file_path = entry_text_file.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a text file for the message")
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                message = "FILE:" + f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read text file: {e}")
            return

    if not message:
        messagebox.showerror("Error", "The message is empty.")
        return

    encrypted_message = encrypt_message(message, password, algorithm)
    try:
        image = Image.open(image_path)
        encoded_image = stepic.encode(image, encrypted_message.encode())
        save_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if save_path:
            encoded_image.save(save_path)
            messagebox.showinfo("Success", "Data hidden and saved successfully!")
            log_operation("Encoded", f"Saved: {save_path} | Algorithm: {algorithm}")
            clear_fields()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to hide data: {e}")
