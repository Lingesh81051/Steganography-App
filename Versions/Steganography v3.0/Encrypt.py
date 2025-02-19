import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image
import stepic
import Stegano

def process_encode():
    # Retrieve widget values from the Stegano module globals
    image_path = Stegano.entry_image_path_encode.get()
    password = Stegano.password_var_encode.get()
    algorithm = Stegano.encryption_algo.get()

    if not image_path or not password:
        messagebox.showerror("Error", "Please select an image and enter a password")
        return

    if Stegano.message_input_option.get() == "type":
        message = Stegano.text_message_encode.get("1.0", tk.END).strip()
    else:
        file_path = Stegano.entry_text_file.get()
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

    # Use the common helper to encrypt the message
    encrypted_msg = Stegano.encrypt_message(message, password, algorithm)
    try:
        image = Image.open(image_path)
        encoded_image = stepic.encode(image, encrypted_msg.encode())
        save_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if save_path:
            encoded_image.save(save_path)
            messagebox.showinfo("Success", "Data hidden and saved successfully!")
            Stegano.log_operation("Encoded", f"Saved: {save_path} | Algorithm: {algorithm}")
            Stegano.clear_fields()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to hide data: {e}")

if __name__ == "__main__":
    # Launch the encryption GUI and pass the process function.
    Stegano.run_encrypt_gui(process_encode)
