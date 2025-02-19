# Decrypt.py
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import stepic

def decode_message(entry_image_path, entry_password, encryption_algo, text_message_widget, 
                   decrypt_message, log_operation, GENERIC_ERROR):
    image_path = entry_image_path.get()
    password = entry_password.get()
    algorithm = encryption_algo.get()

    if not image_path or not password:
        messagebox.showerror("Error", "Please select an image and enter a password")
        return

    try:
        image = Image.open(image_path)
        extracted_bytes = stepic.decode(image)
        if isinstance(extracted_bytes, bytes):
            extracted_message = extracted_bytes.decode()
        else:
            extracted_message = extracted_bytes

        decrypted_message = decrypt_message(extracted_message, password, algorithm)
        if decrypted_message == GENERIC_ERROR:
            messagebox.showerror("Error", GENERIC_ERROR)
            return

        text_message_widget.config(state="normal")
        text_message_widget.delete("1.0", tk.END)
        text_message_widget.insert(tk.END, decrypted_message)
        text_message_widget.config(state="disabled")

        if decrypted_message.startswith("FILE:"):
            file_content = decrypted_message[len("FILE:"):]
            text_message_widget.config(state="normal")
            text_message_widget.delete("1.0", tk.END)
            text_message_widget.insert(tk.END, file_content)
            text_message_widget.config(state="disabled")
            if messagebox.askyesno("Save as Text File", "The revealed data is from a text file. Save it as a text file?"):
                save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                         filetypes=[("Text Files", "*.txt")])
                if save_path:
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(file_content)
        messagebox.showinfo("Success", "Data revealed successfully!")
        log_operation("Decoded", f"Image: {image_path} | Algorithm: {algorithm}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to reveal data: {e}")
