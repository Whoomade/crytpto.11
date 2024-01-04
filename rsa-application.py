import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii

def generateKeys():
    key = RSA.generate(3072)
    private_key = key.exportKey()
    public_key = key.publickey().exportKey()
    with open('./keys/privateKey.pem', 'wb') as private_file:
        private_file.write(private_key)
    with open('./keys/publicKey.pem', 'wb') as public_file:
        public_file.write(public_key)

def loadKeys():
    with open('./keys/privateKey.pem', 'rb') as private_file:
        private_key = RSA.importKey(private_file.read())
    with open('./keys/publicKey.pem', 'rb') as public_file:
        public_key = RSA.importKey(public_file.read())
    return private_key, public_key

def decrypt(encrypted):
    private_key = RSA.importKey(open("./keys/privateKey.pem").read())
    if not private_key:
        messagebox.showerror("Could find keys in keys/ directory")
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(encrypted)
    return decrypted

def encrypt(msg):
    public_key = RSA.importKey(open("./keys/publicKey.pem").read())
    if not public_key:
        messagebox.showerror("Could find keys in keys/ directory")
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(msg)
    return encrypted

def encrypt_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'r') as file:
            plain_text = file.read()
        crypto = binascii.hexlify(encrypt(plain_text.encode()))
        new_filepath = filepath + '.encrypted'
        with open(new_filepath, 'wb') as file:
            file.write(crypto)

def decrypt_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'rb') as file:
            crypto = file.read()
            
        plain_text = decrypt(binascii.unhexlify(crypto))

        new_filepath = filepath.replace('.encrypted', '')
        with open(new_filepath, 'w') as file:
            file.write(str(plain_text)[2:-1])

def encrypt_message():
    plain_text_message = plain_text.get()  # get the plain text message from the text widget
    encrypted_message = binascii.hexlify(encrypt(plain_text_message.encode()))
    encrypted_text.delete(0, tk.END)  # clear the text widget
    encrypted_text.insert(0, encrypted_message.decode())  # insert the encrypted message

def read_file():
    file = filedialog.askopenfile(mode='r', filetypes=[("Text Files", "*.txt")])
    if file is None:
        return
    plain_text.delete(0, tk.END)  # clear the text widget
    plain_text.insert(0, file.read())
    file.close()

def save_file():
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    with open(filename, "wb") as file:
        crypto = encrypted_text.get()  # get the encrypted text from the text widget
        crypto = crypto.encode()
        file.write(crypto)

def verify_message():
    plain_text_message = plain_text.get()  # get the plain text message from the text widget
    signature = signature_text.get()
    signature = bytes.fromhex(signature)
    h = SHA256.new(plain_text_message.encode())
    key = RSA.importKey(open("./keys/publicKey.pem").read())  # import the private key from file
    if not key:
        messagebox.showerror("Could find keys in keys/ directory")
    try:
        pkcs1_15.new(key).verify(h, signature)
        messagebox.showinfo("Verify Successful", "The signature is valid.")
    except:
        messagebox.showerror("Verify Failed", "The signature is not valid.")

def sign_message():
    plain_text_message = plain_text.get()  # get the plain text message from the text widget
    h = SHA256.new(plain_text_message.encode())
    key = RSA.importKey(open("./keys/privateKey.pem").read())  # import the private key from file
    if not key:
        messagebox.showerror("Could find keys in keys/ directory")
    signature = pkcs1_15.new(key).sign(h)
    signature_text.delete(0, tk.END)  # clear the text widget
    signature_text.insert(0, signature.hex())

root = tk.Tk()
root.title("RSA Encryption Tool \n By Humaid")
root.config(background="brown")
buttonBG = "beige"
textColor = "black"

# Create a style for rounded text entry
style = ttk.Style(root)
style.configure('Rounded.TEntry', borderwidth=100, relief='flat', background='white', padding=(10, 10))

# Create a label and a text widget for the plain text
plain_text_label = tk.Label(root, text="Plain Text:", fg=textColor, bg=buttonBG)
plain_text_label.pack()
plain_text = ttk.Entry(root, style='Rounded.TEntry')
plain_text.pack()

# Create a label and a text widget for the encrypted text
encrypted_text_label = tk.Label(root, text="Encrypted Text:", fg=textColor, bg=buttonBG)
encrypted_text_label.pack()
encrypted_text = ttk.Entry(root, style='Rounded.TEntry')
encrypted_text.pack()

# Create a label for signature text
signature_text_label = tk.Label(root, text="Signature Text", fg=textColor, bg=buttonBG)
signature_text_label.pack()

# Using ttk.Entry for rounded corners
signature_text = ttk.Entry(root, style='Rounded.TEntry')
signature_text.pack()

# Create buttons and set their commands
buttons = [
    ("Generate Keys", generateKeys),
    ("Load Keys", loadKeys),
    ("Encrypt File", encrypt_file),
    ("Decrypt File", decrypt_file),
    ("Encrypt", encrypt_message),
    ("Save to File", save_file),
    ("Read from File", read_file),
    ("Sign", sign_message),
    ("Verify", verify_message)
]

for text, command in buttons:
    button = tk.Button(root, text=text, command=command, bg=buttonBG, fg=textColor)
    button.pack(pady=5)

root.mainloop()
