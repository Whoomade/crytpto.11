import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii

def generate_keys():
    key = RSA.generate(3072)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open('./keys/privateKey.pem', 'wb') as private_file:
        private_file.write(private_key)
    with open('./keys/publicKey.pem', 'wb') as public_file:
        public_file.write(public_key)
    messagebox.showinfo("Success", "Keys generated successfully.")

def load_keys():
    try:
        with open('./keys/privateKey.pem', 'rb') as private_file:
            private_key = RSA.import_key(private_file.read())
        with open('./keys/publicKey.pem', 'rb') as public_file:
            public_key = RSA.import_key(public_file.read())
        messagebox.showinfo("Success", "Keys loaded successfully.")
        return private_key, public_key
    except FileNotFoundError:
        messagebox.showerror("Error", "Key files not found in keys/ directory")

def decrypt(encrypted):
    private_key = RSA.import_key(open("./keys/privateKey.pem").read())
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(encrypted)
    return decrypted

def encrypt(msg):
    public_key = RSA.import_key(open("./keys/publicKey.pem").read())
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(msg)
    return encrypted

def decrypt_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'rb') as file:
            crypto = file.read()

        try:
            plain_text = decrypt(binascii.unhexlify(crypto))
            messagebox.showinfo("Success", "File decrypted successfully.")
        except ValueError:
            messagebox.showerror("Error", "Invalid encrypted file or key")

        new_filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if new_filepath:
            with open(new_filepath, 'w') as file:
                file.write(str(plain_text)[2:-1])

def encrypt_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'r') as file:
            plain_text = file.read()
        try:
            crypto = binascii.hexlify(encrypt(plain_text.encode()))
            messagebox.showinfo("Success", "File encrypted successfully.")
        except ValueError:
            messagebox.showerror("Error", "Invalid key")
            return

        new_filepath = filedialog.asksaveasfilename(defaultextension=".encrypted", filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")])
        if new_filepath:
            with open(new_filepath, 'wb') as file:
                file.write(crypto)

def sign_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'rb') as file:
            file_content = file.read()

        private_key = load_keys()[0]
        if private_key:
            h = SHA256.new(file_content)
            signature = pkcs1_15.new(private_key).sign(h)

            # Specify the new file path for saving the signature
            new_filepath = filepath + '.signature'
            with open(new_filepath, 'wb') as file:
                file.write(signature)
            messagebox.showinfo("Success", "File signed successfully.")
        else:
            messagebox.showerror("Error", "Private key not found")

def verify_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'rb') as file:
            file_content = file.read()

        signature_filepath = filedialog.askopenfilename()
        if signature_filepath:
            with open(signature_filepath, 'rb') as signature_file:
                signature = signature_file.read()

            public_key = load_keys()[1]
            if public_key:
                h = SHA256.new(file_content)
                try:
                    pkcs1_15.new(public_key).verify(h, signature)
                    messagebox.showinfo("Verify Successful", "The signature is valid. Verification successful!")
                except ValueError:
                    messagebox.showerror("Verify Failed", "The signature is not valid.")
            else:
                messagebox.showerror("Error", "Public key not found")

root = tk.Tk()
root.title("RSA Encryption Tool by Humaid")
root.config(background="brown")
button_bg = "beige"
text_color = "black"

# Create buttons and set their commands
buttons = [
    ("Generate Keys", generate_keys),
    ("Load Keys", load_keys),
    ("Encrypt File", encrypt_file),
    ("Decrypt File", decrypt_file),
    ("Sign File", sign_file),
    ("Verify File", verify_file)
]

for text, command in buttons:
    button = tk.Button(root, text=text, command=command, bg=button_bg, fg=text_color)
    button.pack(pady=5)

root.mainloop()





