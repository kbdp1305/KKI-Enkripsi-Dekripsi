import tkinter as tk
from cryptography.fernet import Fernet as fernet

class App:
    def __init__(self, master):
        self.master = master
        master.title("Encryption")

        # Create a label for the message
        self.label_message = tk.Label(master, text="Message:")
        self.label_message.grid(row=0, column=0)

        # Create an entry box for the message
        self.entry_message = tk.Entry(master)
        self.entry_message.grid(row=0, column=1)

        # Create a button to encrypt the message
        self.button_encrypt = tk.Button(master, text="Encrypt", command=self.encrypt_message)
        self.button_encrypt.grid(row=1, column=0)

        # Create a button to decrypt the message
        self.button_decrypt = tk.Button(master, text="Decrypt", command=self.decrypt_message)
        self.button_decrypt.grid(row=1, column=1)

    # def generate_key(self):
    #     key = fernet.Fernet.generate_key()
    #     with open("secret.key", "wb") as key_file:
    #         key_file.write(key)

    # def load_key(self):
    #     return open("secret.key", "rb").read()
    
    def caesar_cipher(self,plaintext):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha() and char.isupper():
            # Shift 3 posisi ke kanan dalam alfabet
                shifted_char = chr((ord(char) - 65 + 3) % 26 + 65)
                ciphertext += shifted_char
            elif char.isalpha() and char.islower():
                if ord(char)<120 :
                    ciphertext+=chr(ord(char)+3)
                else :
                    shifted_char = chr(ord(char)%26 + 81)
                    ciphertext+=shifted_char
            else :
                ciphertext+=char


        return ciphertext

    def encrypt_message(self):
        
        message = self.entry_message.get()
        # # key = self.load_key()
        # encoded_message = message.encode()
        # # f = fernet.Fernet(key)
        encrypted_message = self.caesar_cipher(message)
        self.entry_message.delete(0, tk.END)
        self.entry_message.insert(0, encrypted_message)

    def decrypt_message(self):
        encrypted_message = self.entry_message.get()
        key = self.load_key()
        f = fernet.Fernet(key)
        decrypted_message = f.decrypt(encrypted_message.encode())
        self.entry_message.delete(0, tk.END)
        self.entry_message.insert(0, decrypted_message.decode())

root = tk.Tk()
app = App(root)
root.mainloop()
