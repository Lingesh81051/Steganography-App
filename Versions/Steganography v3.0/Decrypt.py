import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image
import stepic
import Stegano

def process_decode():
    image_path = Stegano.entry_image_path_decode.get()
    password = Stegano.entry_password_decode.get()
    algorithm = Stegano.encryption_algo_decode.get()

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

        decrypted_message = Stegano.decrypt_message(extracted_message, password, algorithm)
        if decrypted_message == Stegano.GENERIC_ERROR:
            messagebox.showerror("Error", Stegano.GENERIC_ERROR)
            return

        Stegano.text_message_decode.config(state="normal")
        Stegano.text_message_decode.delete("1.0", tk.END)
        Stegano.text_message_decode.insert(tk.END, decrypted_message)
        Stegano.text_message_decode.config(state="disabled")
        
        if decrypted_message.startswith("FILE:"):
            file_content = decrypted_message[len("FILE:"):]
            Stegano.text_message_decode.config(state="normal")
            Stegano.text_message_decode.delete("1.0", tk.END)
            Stegano.text_message_decode.insert(tk.END, file_content)
            Stegano.text_message_decode.config(state="disabled")
            if messagebox.askyesno("Save as Text File", "The revealed data is from a text file. Save it as a text file?"):
                save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                         filetypes=[("Text Files", "*.txt")])
                if save_path:
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(file_content)
        messagebox.showinfo("Success", "Data revealed successfully!")
        Stegano.log_operation("Decoded", f"Image: {image_path} | Algorithm: {algorithm}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to reveal data: {e}")

if __name__ == "__main__":
    Stegano.run_decrypt_gui(process_decode)
