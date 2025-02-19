import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64
import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress the specific deprecation warning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning, module="cryptography.hazmat.primitives.ciphers.algorithms")

# --- Cryptography Functions (Same as before, but put into a class) ---

class CryptoHandler:
    def __init__(self):
        self.private_key_b = None
        self.public_key_b = None
        self.tdes_key = None
        self.decrypted_tdes_key = None

    def generate_rsa_key_pair(self):
        """Generates an RSA key pair (public and private)."""
        self.private_key_b = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key_b = self.private_key_b.public_key() # Get public key FROM private key
        return self.serialize_key(self.public_key_b)  # Return public key PEM

    def serialize_key(self, key):
        """Serializes a key (public or private) to PEM format."""
        if isinstance(key, rsa.RSAPrivateKey):
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:  # isinstance(key, rsa.RSAPublicKey):
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return pem.decode()

    def deserialize_key(self, pem_str, private=False):
        """Deserializes a key from PEM format."""
        pem = pem_str.encode()
        if private:
            key = serialization.load_pem_private_key(
                pem,
                password=None,
                backend=default_backend()
            )
        else:
            key = serialization.load_pem_public_key(
                pem,
                backend=default_backend()
            )
        return key

    def rsa_encrypt(self, public_key, plaintext):
        """Encrypts data using RSA."""
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def rsa_decrypt(self, private_key, ciphertext):
        """Decrypts data using RSA."""
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def generate_tdes_key(self):
        """Generates a random 168-bit (24-byte) Triple DES key."""
        self.tdes_key = os.urandom(24)
        return base64.b64encode(self.tdes_key).decode() # Return base64 encoded key

    def tdes_encrypt(self, key, plaintext):
        """Encrypts data using Triple DES in CBC mode."""
        iv = os.urandom(8)  # IV must be 8 bytes for DES
        padder = sym_padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # Prepend IV to ciphertext

    def tdes_decrypt(self, key, ciphertext):
        """Decrypts data using Triple DES in CBC mode."""
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode()

    def flip_bit(self, ciphertext, bit_index):
        """Flips a bit in the ciphertext."""
        byte_index = bit_index // 8
        bit_offset = bit_index % 8

        if byte_index >= len(ciphertext):
            raise ValueError("Bit index out of range")

        modified_ciphertext = bytearray(ciphertext)  # Convert to bytearray for modification
        modified_ciphertext[byte_index] ^= (1 << bit_offset)  # XOR operation to flip the bit
        return bytes(modified_ciphertext)


# --- GUI Functions ---

def generate_keys_ui():
    public_key_pem = crypto_handler.generate_rsa_key_pair()
    public_key_text.delete("1.0", tk.END)
    public_key_text.insert("1.0", public_key_pem)
    tdes_key_text.delete("1.0", tk.END)
    tdes_key_text.insert("1.0", crypto_handler.generate_tdes_key())
    status_label.config(text="RSA and Triple DES keys generated.", foreground="green")  # Corrected

def encrypt_message_ui():
    try:
        plaintext = plaintext_input.get("1.0", tk.END).strip()
        if not plaintext:
          messagebox.showerror("Error", "Please enter a message to encrypt.")
          return
        public_key_pem = public_key_text.get("1.0", tk.END).strip()
        tdes_key_base64 = tdes_key_text.get("1.0", tk.END).strip()
        if not public_key_pem or not tdes_key_base64 :
            messagebox.showerror("Error", "Please generate keys first.")
            return

        #RSA Key Exchange.
        public_key = crypto_handler.deserialize_key(public_key_pem)
        tdes_key = base64.b64decode(tdes_key_base64)
        encrypted_tdes_key = crypto_handler.rsa_encrypt(public_key, tdes_key)

        #Person B actions
        crypto_handler.decrypted_tdes_key = crypto_handler.rsa_decrypt(crypto_handler.private_key_b, encrypted_tdes_key)

        # TDES encryption
        ciphertext = crypto_handler.tdes_encrypt(tdes_key, plaintext)
        ciphertext_text.delete("1.0", tk.END)
        ciphertext_text.insert("1.0", base64.b64encode(ciphertext).decode())
        status_label.config(text="Message encrypted.", foreground="green")  # Corrected
        decrypt_button.config(state=tk.NORMAL) #Enable decrypt button

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))
        status_label.config(text="Encryption failed.", foreground="red")  # Corrected

def decrypt_message_ui():
    try:
        ciphertext_base64 = ciphertext_text.get("1.0", tk.END).strip()
        if not ciphertext_base64:
            messagebox.showerror("Error", "No ciphertext to decrypt.")
            return
        if not crypto_handler.decrypted_tdes_key:
            messagebox.showerror("Error", "Triple DES key not decrypted. Key exchange incomplete.")
            return

        ciphertext = base64.b64decode(ciphertext_base64)
        decrypted_plaintext = crypto_handler.tdes_decrypt(crypto_handler.decrypted_tdes_key, ciphertext)
        decrypted_text.delete("1.0", tk.END)
        decrypted_text.insert("1.0", decrypted_plaintext)
        status_label.config(text="Message decrypted.", foreground="green")  # Corrected
        error_demo_button.config(state=tk.NORMAL)

    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        status_label.config(text="Decryption failed.", foreground="red") # Corrected

def demonstrate_error_ui():
    try:
        ciphertext_base64 = ciphertext_text.get("1.0", tk.END).strip()
        bit_index_str = bit_index_entry.get().strip()

        if not ciphertext_base64 or not bit_index_str:
           messagebox.showerror("Error", "Ciphertext and bit index are required.")
           return

        bit_index = int(bit_index_str)
        ciphertext = base64.b64decode(ciphertext_base64)
        modified_ciphertext = crypto_handler.flip_bit(ciphertext, bit_index)
        modified_ciphertext_text.delete("1.0", tk.END)
        modified_ciphertext_text.insert("1.0", base64.b64encode(modified_ciphertext).decode())

        decrypted_modified_plaintext = crypto_handler.tdes_decrypt(crypto_handler.decrypted_tdes_key, modified_ciphertext)
        decrypted_modified_text.delete("1.0", tk.END)
        decrypted_modified_text.insert("1.0", decrypted_modified_plaintext)
        status_label.config(text="Bit flipped and decrypted.", foreground="orange")  # Corrected

    except ValueError:
        messagebox.showerror("Error", "Invalid bit index.  Must be an integer.")
        status_label.config(text="Error demonstration failed.", foreground="red")  # Corrected
    except Exception as e:
        messagebox.showerror("Error", str(e))
        status_label.config(text="Error demonstration failed.", foreground="red") # Corrected

# --- Main GUI Setup ---

crypto_handler = CryptoHandler()  # Create an instance of the crypto handler

root = tk.Tk()
root.title("Hybrid Cipher Demo")

# Main Layout
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Key Generation Section
key_gen_frame = ttk.LabelFrame(main_frame, text="Key Generation", padding="5")
key_gen_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)

generate_button = ttk.Button(key_gen_frame, text="Generate Keys", command=generate_keys_ui)
generate_button.grid(row=0, column=0, padx=5, pady=5)

public_key_label = ttk.Label(key_gen_frame, text="Public Key (PEM):")
public_key_label.grid(row=1, column=0, sticky=tk.W, padx=5)
public_key_text = scrolledtext.ScrolledText(key_gen_frame, width=50, height=5, wrap=tk.WORD)
public_key_text.grid(row=2, column=0, padx=5, pady=5)

tdes_key_label = ttk.Label(key_gen_frame, text="Triple DES Key (Base64):")
tdes_key_label.grid(row=3, column=0, sticky=tk.W, padx=5)
tdes_key_text = scrolledtext.ScrolledText(key_gen_frame, width=50, height=2, wrap=tk.WORD)
tdes_key_text.grid(row=4, column=0, padx=5, pady=5)


# Encryption/Decryption Section
enc_dec_frame = ttk.LabelFrame(main_frame, text="Encryption/Decryption", padding="5")
enc_dec_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)

plaintext_label = ttk.Label(enc_dec_frame, text="Plaintext:")
plaintext_label.grid(row=0, column=0, sticky=tk.W, padx=5)
plaintext_input = scrolledtext.ScrolledText(enc_dec_frame, width=50, height=3, wrap=tk.WORD)
plaintext_input.grid(row=1, column=0, padx=5, pady=5)

encrypt_button = ttk.Button(enc_dec_frame, text="Encrypt", command=encrypt_message_ui)
encrypt_button.grid(row=2, column=0, padx=5, pady=5)

ciphertext_label = ttk.Label(enc_dec_frame, text="Ciphertext (Base64):")
ciphertext_label.grid(row=3, column=0, sticky=tk.W, padx=5)
ciphertext_text = scrolledtext.ScrolledText(enc_dec_frame, width=50, height=3, wrap=tk.WORD)
ciphertext_text.grid(row=4, column=0, padx=5, pady=5)

decrypt_button = ttk.Button(enc_dec_frame, text="Decrypt", command=decrypt_message_ui, state=tk.DISABLED)
decrypt_button.grid(row=5, column=0, padx=5, pady=5)

decrypted_label = ttk.Label(enc_dec_frame, text="Decrypted Plaintext:")
decrypted_label.grid(row=6, column=0, sticky=tk.W, padx=5)
decrypted_text = scrolledtext.ScrolledText(enc_dec_frame, width=50, height=3, wrap=tk.WORD)
decrypted_text.grid(row=7, column=0, padx=5, pady=5)

# Error Demonstration Section
error_demo_frame = ttk.LabelFrame(main_frame, text="Error Demonstration", padding="5")
error_demo_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)

bit_index_label = ttk.Label(error_demo_frame, text="Bit Index to Flip:")
bit_index_label.grid(row=0, column=0, sticky=tk.W, padx=5)
bit_index_entry = ttk.Entry(error_demo_frame, width=10)
bit_index_entry.grid(row=0, column=1, padx=5, pady=5)

error_demo_button = ttk.Button(error_demo_frame, text="Flip Bit and Decrypt", command=demonstrate_error_ui, state=tk.DISABLED)
error_demo_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

modified_ciphertext_label = ttk.Label(error_demo_frame, text="Modified Ciphertext (Base64):")
modified_ciphertext_label.grid(row=2, column=0, sticky=tk.W, padx=5)
modified_ciphertext_text = scrolledtext.ScrolledText(error_demo_frame, width=50, height=3, wrap=tk.WORD)
modified_ciphertext_text.grid(row=3, column=0, padx=5, pady=5)

decrypted_modified_label = ttk.Label(error_demo_frame, text="Decrypted Modified Plaintext:")
decrypted_modified_label.grid(row=4, column=0, sticky=tk.W, padx=5)
decrypted_modified_text = scrolledtext.ScrolledText(error_demo_frame, width=50, height=3, wrap=tk.WORD)
decrypted_modified_text.grid(row=5, column=0, padx=5, pady=5)


# Status Label (for general messages)
status_label = ttk.Label(main_frame, text="", font=("Arial", 10))
status_label.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)

#
status_label.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)

# Make the GUI resizable
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
main_frame.columnconfigure(0, weight=1)


root.mainloop()