import time
import argparse
import string
import random
import tkinter as tk
from tkinter import ttk, scrolledtext

# (Cipher functions from previous response - paste them here)
# ... (paste create_playfair_matrix, preprocess_playfair_plaintext, etc. here) ...
# Playfair Cipher Functions
def create_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    seen = set()
    key_unique = []
    for char in key:
        if char not in seen and char.isalpha():
            seen.add(char)
            key_unique.append(char)
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    for char in alphabet:
        if char not in seen:
            key_unique.append(char)
    matrix = [key_unique[i*5:(i+1)*5] for i in range(5)]
    return matrix

def preprocess_playfair_plaintext(plaintext):
    plaintext = plaintext.upper().replace('J', 'I')
    plaintext = ''.join([c for c in plaintext if c.isalpha()])
    processed = []
    i = 0
    n = len(plaintext)
    while i < n:
        if i == n - 1:
            processed.append(plaintext[i] + 'X')
            i += 1
        else:
            a = plaintext[i]
            b = plaintext[i+1]
            if a == b:
                processed.append(a + 'X')
                i += 1
            else:
                processed.append(a + b)
                i += 2
    processed_text = ''.join(processed)
    # if len(processed_text) % 2 != 0:  # No need. Handled inside the loop
    #     processed_text += 'X'
    return processed_text

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return (row, col)
    return (None, None)

def playfair_encrypt_pair(matrix, a, b):
    row_a, col_a = find_position(matrix, a)
    row_b, col_b = find_position(matrix, b)
    if row_a == row_b:
        encrypted_a = matrix[row_a][(col_a + 1) % 5]
        encrypted_b = matrix[row_b][(col_b + 1) % 5]
    elif col_a == col_b:
        encrypted_a = matrix[(row_a + 1) % 5][col_a]
        encrypted_b = matrix[(row_b + 1) % 5][col_b]
    else:
        encrypted_a = matrix[row_a][col_b]
        encrypted_b = matrix[row_b][col_a]
    return encrypted_a + encrypted_b

def playfair_decrypt_pair(matrix, a, b):
    row_a, col_a = find_position(matrix, a)
    row_b, col_b = find_position(matrix, b)
    if row_a == row_b:
        decrypted_a = matrix[row_a][(col_a - 1) % 5]
        decrypted_b = matrix[row_b][(col_b - 1) % 5]
    elif col_a == col_b:
        decrypted_a = matrix[(row_a - 1) % 5][col_a]
        decrypted_b = matrix[(row_b - 1) % 5][col_b]
    else:
        decrypted_a = matrix[row_a][col_b]
        decrypted_b = matrix[row_b][col_a]
    return decrypted_a + decrypted_b

def playfair_encrypt(plaintext, key):
    matrix = create_playfair_matrix(key)
    processed_text = preprocess_playfair_plaintext(plaintext)
    ciphertext = []
    for i in range(0, len(processed_text), 2):
        a = processed_text[i]
        b = processed_text[i+1]
        ciphertext.append(playfair_encrypt_pair(matrix, a, b))
    return ''.join(ciphertext)

def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)
    processed_text = []
    for i in range(0, len(ciphertext), 2):
        a = ciphertext[i]
        b = ciphertext[i+1]
        processed_text.append(playfair_decrypt_pair(matrix, a, b))
    decrypted_text = ''.join(processed_text)

    cleaned_text = ""
    i = 0
    while i < len(decrypted_text):
        if i + 1 < len(decrypted_text):
            if decrypted_text[i] == decrypted_text[i + 1] and decrypted_text[i+1] == 'X':
                # This case shouldn't happen in proper Playfair.  It's a result of
                # the Rail Fence potentially disrupting digraphs. We'll skip
                # the second char
                cleaned_text += decrypted_text[i]
                i+=2

            elif decrypted_text[i+1] == 'X':
                # Check if current char is the same with the next char after X,
                # if so, remove X, else, include current char
                if i + 2 < len(decrypted_text):
                  if decrypted_text[i] == decrypted_text[i+2]:
                      cleaned_text += decrypted_text[i]
                      i += 2
                  else:
                      cleaned_text += decrypted_text[i]
                      i += 1 # Only skip X
                else: #X at the end and not padding
                    cleaned_text += decrypted_text[i]
                    i += 1

            else:
                cleaned_text += decrypted_text[i]
                cleaned_text += decrypted_text[i + 1]
                i += 2
        else:  # Last character
            if decrypted_text[i] != 'X':  # Only add if it's not a padding X
                cleaned_text += decrypted_text[i]
            i += 1
    return cleaned_text

# Rail Fence Cipher Functions

def rail_fence_encrypt(plaintext, depth):
    if depth == 1:
        return plaintext
    rails = [[] for _ in range(depth)]
    current_row = 0
    direction = 1
    for char in plaintext:
        rails[current_row].append(char)
        current_row += direction
        if current_row == depth - 1 or current_row == 0:
            direction *= -1
    ciphertext = []
    for rail in rails:
        ciphertext.extend(rail)
    return ''.join(ciphertext)

def rail_fence_decrypt(ciphertext, depth):
    if depth == 1:
        return ciphertext
    n = len(ciphertext)
    rail_lengths = [0] * depth
    cycle = 2 * (depth - 1)
    full_cycles, remainder = divmod(n, cycle)
    for i in range(depth):
        rail_lengths[i] = full_cycles
    for i in range(1, depth - 1):
        rail_lengths[i] *= 2
    for i in range(remainder):
        if i < depth:
            rail_lengths[i] += 1
        else:
            rail_lengths[cycle - i] += 1
    rails = []
    index = 0
    for length in rail_lengths:
        rails.append(ciphertext[index:index+length])
        index += length
    plaintext = []
    current_row = 0
    direction = 1
    row_indices = [0] * depth
    for _ in range(n):
        plaintext.append(rails[current_row][row_indices[current_row]])
        row_indices[current_row] += 1
        current_row += direction
        if current_row == 0 or current_row == depth - 1:
            direction *= -1
    return ''.join(plaintext)

# Product Cipher Functions

def product_encrypt(plaintext, playfair_key, rail_depth):
    playfair_out = playfair_encrypt(plaintext, playfair_key)
    rail_out = rail_fence_encrypt(playfair_out, rail_depth)
    return rail_out

def product_decrypt(ciphertext, playfair_key, rail_depth):
    rail_out = rail_fence_decrypt(ciphertext, rail_depth)
    playfair_out = playfair_decrypt(rail_out, playfair_key)
    return playfair_out


def run_analysis(plaintext, playfair_key, rail_depth):
    """Runs analysis on Playfair, Rail Fence, and Product ciphers."""
    results = {}

    # Playfair Analysis
    start_time = time.time()
    pf_ciphertext = playfair_encrypt(plaintext, playfair_key)
    pf_encrypt_time = time.time() - start_time

    start_time = time.time()
    pf_decrypted = playfair_decrypt(pf_ciphertext, playfair_key)
    pf_decrypt_time = time.time() - start_time

    results['playfair'] = {
        'ciphertext': pf_ciphertext,
        'decrypted': pf_decrypted,
        'encrypt_time': pf_encrypt_time,
        'decrypt_time': pf_decrypt_time,
    }

    # Rail Fence Analysis
    start_time = time.time()
    rf_ciphertext = rail_fence_encrypt(plaintext, rail_depth)
    rf_encrypt_time = time.time() - start_time

    start_time = time.time()
    rf_decrypted = rail_fence_decrypt(rf_ciphertext, rail_depth)
    rf_decrypt_time = time.time() - start_time

    results['rail_fence'] = {
        'ciphertext': rf_ciphertext,
        'decrypted': rf_decrypted,
        'encrypt_time': rf_encrypt_time,
        'decrypt_time': rf_decrypt_time,
    }

    # Product Cipher Analysis
    start_time = time.time()
    prod_ciphertext = product_encrypt(plaintext, playfair_key, rail_depth)
    prod_encrypt_time = time.time() - start_time

    start_time = time.time()
    prod_decrypted = product_decrypt(prod_ciphertext, playfair_key, rail_depth)
    prod_decrypt_time = time.time() - start_time

    results['product'] = {
        'ciphertext': prod_ciphertext,
        'decrypted': prod_decrypted,
        'encrypt_time': prod_encrypt_time,
        'decrypt_time': prod_decrypt_time,
    }

    return results


def encrypt_decrypt_action():
    """Handles encryption/decryption based on UI input."""
    plaintext = plaintext_entry.get()
    playfair_key = key_entry.get()
    rail_depth = int(depth_entry.get())
    operation = operation_var.get()  # 'encrypt' or 'decrypt'

    if operation == 'encrypt':
        ciphertext = product_encrypt(plaintext, playfair_key, rail_depth)
        result_text.delete('1.0', tk.END)
        result_text.insert('1.0', f"Ciphertext: {ciphertext}")
    elif operation == 'decrypt':
        ciphertext = ciphertext_entry.get()  # Get ciphertext from entry
        decrypted_text = product_decrypt(ciphertext, playfair_key, rail_depth)
        result_text.delete('1.0', tk.END)
        result_text.insert('1.0', f"Decrypted Text: {decrypted_text}")

def analyze_action():
    """Handles analysis based on UI input."""
    plaintext = plaintext_entry.get()
    playfair_key = key_entry.get()
    
    # Check for valid depth
    try:
        rail_depth = int(depth_entry.get())
        if rail_depth <= 0:
            raise ValueError("Depth must be a positive integer.")
    except ValueError as e:
        result_text.delete('1.0', tk.END)
        result_text.insert('1.0', f"Error: Invalid depth. {e}")
        return

    analysis_results = run_analysis(plaintext, playfair_key, rail_depth)

    # Display results
    result_text.delete('1.0', tk.END)  # Clear previous results

    for cipher_name, results in analysis_results.items():
        result_text.insert(tk.END, f"\n--- {cipher_name.title()} Cipher ---\n")
        result_text.insert(tk.END, f"Ciphertext: {results['ciphertext']}\n")
        result_text.insert(tk.END, f"Decrypted: {results['decrypted']}\n")
        result_text.insert(tk.END, f"Encryption Time: {results['encrypt_time']:.6f} seconds\n")
        result_text.insert(tk.END, f"Decryption Time: {results['decrypt_time']:.6f} seconds\n")

    # Add security analysis section
    result_text.insert(tk.END, "\n--- Security Analysis ---\n")
    result_text.insert(tk.END, "Playfair Cipher:\n")
    result_text.insert(tk.END, "  - More secure than simple substitution ciphers.\n")
    result_text.insert(tk.END, "  - Vulnerable to frequency analysis of digraphs.\n")
    result_text.insert(tk.END, "  - Key length significantly impacts security.\n")

    result_text.insert(tk.END, "\nRail Fence Cipher:\n")
    result_text.insert(tk.END, "  - Very weak on its own.\n")
    result_text.insert(tk.END, "  - Easily broken with known plaintext attacks.\n")
    result_text.insert(tk.END, "  - Depth provides minimal security.\n")

    result_text.insert(tk.END, "\nProduct Cipher (Playfair + Rail Fence):\n")
    result_text.insert(tk.END, "  - Slightly more secure than either cipher alone.\n")
    result_text.insert(tk.END, "  - Still vulnerable to cryptanalysis.\n")
    result_text.insert(tk.END, "  - Combining weaknesses doesn't create strong security.\n")
    result_text.insert(tk.END, "  - Consider using modern ciphers like AES for strong security.\n")


# --- UI Setup ---
root = tk.Tk()
root.title("Product Cipher (Playfair + Rail Fence)")

# Input Frame
input_frame = ttk.LabelFrame(root, text="Input")
input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

# Operation selection (Encrypt/Decrypt)
operation_var = tk.StringVar(value="encrypt")
encrypt_radio = ttk.Radiobutton(input_frame, text="Encrypt", variable=operation_var, value="encrypt")
decrypt_radio = ttk.Radiobutton(input_frame, text="Decrypt", variable=operation_var, value="decrypt")
encrypt_radio.grid(row=0, column=0, padx=5, pady=5)
decrypt_radio.grid(row=0, column=1, padx=5, pady=5)


# Plaintext Input
plaintext_label = ttk.Label(input_frame, text="Plaintext:")
plaintext_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
plaintext_entry = ttk.Entry(input_frame, width=40)
plaintext_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

# Ciphertext input (for decryption)
ciphertext_label = ttk.Label(input_frame, text="Ciphertext (for Decrypt):")
ciphertext_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
ciphertext_entry = ttk.Entry(input_frame, width=40)
ciphertext_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")


# Playfair Key Input
key_label = ttk.Label(input_frame, text="Playfair Key:")
key_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
key_entry = ttk.Entry(input_frame, width=40)
key_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

# Rail Fence Depth Input
depth_label = ttk.Label(input_frame, text="Rail Fence Depth:")
depth_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
depth_entry = ttk.Entry(input_frame, width=10)
depth_entry.grid(row=4, column=1, padx=5 , pady=5, sticky="ew")

# Buttons Frame (for better layout)
buttons_frame = ttk.Frame(input_frame)
buttons_frame.grid(row=5, column=0, columnspan=2, pady=5)

# Encrypt/Decrypt Button
encrypt_decrypt_button = ttk.Button(buttons_frame, text="Encrypt/Decrypt", command=encrypt_decrypt_action)
encrypt_decrypt_button.grid(row=0, column=0, padx=5)

# Analyze Button
analyze_button = ttk.Button(buttons_frame, text="Analyze", command=analyze_action)
analyze_button.grid(row=0, column=1, padx=5)



# Result Frame
result_frame = ttk.LabelFrame(root, text="Results")
result_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

# Result Text Area (using scrolledtext for better handling of large output)
result_text = scrolledtext.ScrolledText(result_frame, width=60, height=15, wrap=tk.WORD)
result_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

# Make the result frame expand vertically
root.rowconfigure(1, weight=1)
root.columnconfigure(0, weight=1)
result_frame.rowconfigure(0, weight=1)
result_frame.columnconfigure(0, weight=1)


root.mainloop()