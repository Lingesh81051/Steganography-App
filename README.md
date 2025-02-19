# Steganography App
 A secure steganography app that embeds encrypted messages within digital images, ensuring undetectable data transmission. It features multi-layer protection, supports flexible input options, and provides a user-friendly interface for seamless encoding and decoding.


---

## 🔹 Features 

✅ **Multi-Layer Security** – Combines **encryption & steganography** for enhanced protection.  
✅ **Flexible Input Options** – Users can **type messages** or **upload text files**.  
✅ **Algorithm Selection** – Choose from **AES-128, AES-256, SHA-256, MD5**, or **basic encoding**.  
✅ **User-Friendly Interface** – Intuitive GUI for **seamless encoding & decoding**.  
✅ **Error Detection** – Prevents incorrect decryption with **validations on passwords & algorithms**.  
✅ **Modular Codebase** – **Separate encryption & decryption modules** for maintainability.  

---

## 📂 Project Structure 

```
📁 Secure-Steganography-App  
 ├── 📄 Main.py          # Main interface & GUI logic  
 ├── 📄 Encrypt.py       # Encoding & encryption logic  
 ├── 📄 Decrypt.py       # Decoding & decryption logic  
 ├── 📄 README.md        # Documentation  
 ├── 📄 requirements.txt # Dependencies  
```

---

## 🔧 Installation & Setup 

### 1️⃣ Prerequisites 
Ensure you have **Python 3.8+** installed.  

### 2️⃣ Install Dependencies 
```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Application 
```bash
python Main.py
```

---

## 🛠️ Technologies & Libraries Used 

- **Python** (Programming Language)  
- **Tkinter** (GUI Framework)  
- **Pillow** (Image Processing)  
- **Cryptography** (Encryption Algorithms)  

---

## 🚀 How to Use? 

### 🔒 Encoding (Hiding Data)
1️⃣ Select an **image** to hide the message.  
2️⃣ Choose **message input** (Type manually or Upload file).  
3️⃣ Pick an **encryption algorithm** & enter a **password**.  
4️⃣ Click **"Encode"** to embed data.  
5️⃣ Save the **stego image** (with hidden data).  

### 🔓 Decoding (Revealing Data)
1️⃣ Select the **stego image**.  
2️⃣ Enter the **decryption password**.  
3️⃣ Choose the **correct algorithm**.  
4️⃣ Click **"Decode"** to retrieve the message.  

---

## 🛡️ Security Mechanisms 

🔹 **Steganography + Encryption** → Ensures data remains **hidden & protected**.  
🔹 **Wrong Password/Algorithm Detection** → Prevents incorrect decryption.  
🔹 **Read-Only Decoded Message** → Protects extracted data from modifications.  

---

## 📌 Future Scope

🔸 **Support for Audio/Video Steganography**  
🔸 **Integration with Cloud Storage**  
🔸 **AI-Powered Steganalysis Detection**  
🔸 **Mobile App Version**  

---

## 📄 License
This project is **open-source** and licensed under the **MIT License**.  

---

## 📩 Contact 
For any queries or suggestions, feel free to reach out! 🚀  

---
