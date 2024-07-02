import tkinter as tk
from tkinter import messagebox
import math
import random
import string
import hashlib
import requests
from collections import defaultdict
def convert(seconds):
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60

    return "%d:%02d:%02d" % (hour, minutes, seconds)

def commonly_used(passwd):
    with open('10-million-password-list-top-1000000.txt') as f:
        if passwd in f.read():
            return True
        else:
            return False

def how_many_guesses(passwd):
    number_of_nums = 0
    number_of_letters_lower = 0
    number_of_letters_upper = 0
    number_of_special = 0

    x = commonly_used(passwd)

    has_numbers = any(c.isdigit() for c in passwd)
    has_lowercase = any(c.islower() for c in passwd)
    has_uppercase = any(c.isupper() for c in passwd)
    has_special_chars = any(not c.isalnum() for c in passwd)

    if has_numbers:
        number_of_nums = 10

    if has_lowercase:
        number_of_letters_lower = 26

    if has_uppercase:
        number_of_letters_upper = 26

    if has_special_chars:
        number_of_special = 32

    possible_number_chars = number_of_nums + number_of_letters_lower + number_of_letters_upper + number_of_special
    possible_combinations = possible_number_chars ** len(passwd)

    if x:
        password_entropy = 0
        time_to_crack = 60
        moores = 0
    else:
        password_entropy = math.log(possible_combinations, 2)
        time_to_crack = possible_combinations / 2000000000
        moores = 2 * math.log(time_to_crack, 2)

    return possible_combinations, password_entropy, convert(time_to_crack), moores

def password_generator():
    password_length = length_var.get()
    if password_length < 8 or password_length > 16:
        messagebox.showerror("Error", "Invalid length, please choose a length between 8 and 16")
        return

    lowercase_chars = string.ascii_lowercase
    uppercase_chars = string.ascii_uppercase
    digits = string.digits
    special_chars = string.punctuation

    random_string = [
        random.choice(lowercase_chars),
        random.choice(uppercase_chars),
        random.choice(digits),
        random.choice(special_chars)
    ]

    all_chars = lowercase_chars + uppercase_chars + digits + special_chars
    random_string += random.choices(all_chars, k=password_length - 4)
    random.shuffle(random_string)
    generated_password.set(''.join(random_string))

def is_compromised(passwd):
    sha1 = hashlib.sha1()
    sha1.update(passwd.encode())
    hex_digest = sha1.hexdigest().upper()

    hex_digest_f5 = hex_digest[:5]
    hex_digest_remaining = hex_digest[5:]

    r = requests.get(f"https://api.pwnedpasswords.com/range/{hex_digest_f5}")

    leaked_passwd_freq = defaultdict(int)

    for passwd_freq in r.content.splitlines():
        pass_parts = passwd_freq.split(b":")
        passwd = pass_parts[0].decode()
        freq = pass_parts[1]
        leaked_passwd_freq[passwd] = int(freq)

    if hex_digest_remaining in leaked_passwd_freq:
        return leaked_passwd_freq[hex_digest_remaining]

    return 0

def recommendations(passwd):
    common_check = commonly_used(passwd)
    if common_check:
        result_text.insert(tk.END, "Your password is commonly used.\n")
    else:
        result_text.insert(tk.END, "Your password is not commonly used.\n")

    passwd_length = len(passwd)
    if passwd_length < 8:
        result_text.insert(tk.END, "Your password is too short.\n")
    elif passwd_length > 16:
        result_text.insert(tk.END, "Your password may be too long.\n")
    else:
        result_text.insert(tk.END, "Your password is a good length.\n")

    has_numbers = any(c.isdigit() for c in passwd)
    if not has_numbers:
        result_text.insert(tk.END, "Your password should have at least one number.\n")
    else:
        result_text.insert(tk.END, "Your password has at least one number.\n")

    has_lowercase = any(c.islower() for c in passwd)
    if not has_lowercase:
        result_text.insert(tk.END, "Your password should have at least one lowercase letter.\n")
    else:
        result_text.insert(tk.END, "Your password has at least one lowercase letter.\n")

    has_uppercase = any(c.isupper() for c in passwd)
    if not has_uppercase:
        result_text.insert(tk.END, "Your password should have at least one uppercase letter.\n")
    else:
        result_text.insert(tk.END, "Your password has at least one uppercase letter.\n")

    has_special_chars = any(not c.isalnum() for c in passwd)
    if not has_special_chars:
        result_text.insert(tk.END, "Your password should have at least one special character.\n")
    else:
        result_text.insert(tk.END, "Your password has at least one special character.\n")

    has_space = ' ' in passwd
    if has_space:
        result_text.insert(tk.END, "Your password has a space, which is not allowed.\n")
    else:
        result_text.insert(tk.END, "Your password has no spaces.\n")

def main():
    password = password_entry.get()

    result_text.delete('1.0', tk.END)

    common_checker = commonly_used(password)
    if common_checker:
        messagebox.showinfo("Common Password Check", "Your password is commonly used.")
    else:
        messagebox.showinfo("Common Password Check", "Your password is not commonly used.")

    num_coms, entropy, TTC, moore = how_many_guesses(password)
    result_text.insert(tk.END, f"Number of combinations: {num_coms}\n")
    result_text.insert(tk.END, f"Password entropy: {entropy}\n")
    result_text.insert(tk.END, f"Time to crack: {TTC}\n")
    result_text.insert(tk.END, f"Years before cracked in under an hour: {moore}\n")

    compromise_checker = is_compromised(password)
    if compromise_checker > 0:
        messagebox.showinfo("Compromised Check", f"Your password has been compromised {compromise_checker} times.")
    else:
        messagebox.showinfo("Compromised Check", "No data breaches detected.")

    recommendations(password)


def toggle_password():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
    else:
        password_entry.config(show='*')


root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("600x500")

password_label = tk.Label(root, text="Enter your password:", font=("Arial", 14))
password_label.pack(pady=10)

password_entry = tk.Entry(root, show="*", font=("Arial", 14), width=30)
password_entry.pack(pady=10)

toggle_button = tk.Button(root, text="Show/Hide Password", command=toggle_password, font=("Arial", 14))
toggle_button.pack(pady=10)

check_button = tk.Button(root, text="Check Password", command=main, font=("Arial", 14))
check_button.pack(pady=10)

result_text = tk.Text(root, height=10, width=50, font=("Arial", 12))
result_text.pack(pady=10)

length_var = tk.IntVar(value=8)

length_label = tk.Label(root, text="Password length (8-16):", font=("Arial", 14))
length_label.pack(pady=10)

length_entry = tk.Spinbox(root, from_=8, to=16, textvariable=length_var, font=("Arial", 14))
length_entry.pack(pady=10)

generated_password = tk.StringVar()

generate_button = tk.Button(root, text="Generate Password", command=password_generator, font=("Arial", 14))
generate_button.pack(pady=10)

generated_password_label = tk.Label(root, textvariable=generated_password, font=("Arial", 14))
generated_password_label.pack(pady=10)

root.mainloop()