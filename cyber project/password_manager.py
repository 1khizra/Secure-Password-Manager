from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
import os
import datetime
import random
import string

# === Encryption Setup === #
def load_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    with open("key.key", "rb") as key_file:
        return key_file.read()

f = Fernet(load_key())

def encrypt_password(password):
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return f.decrypt(encrypted_password.encode()).decode()

# === GUI Window === #
window = Tk()
window.title("🔐 Secure Password Manager")
window.geometry("600x750")

# === Save Password === #
def save_password():
    website = entry_website.get()
    username = entry_username.get()
    password = entry_password.get()

    if not website or not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    encrypted_password = encrypt_password(password)
    with open("passwords.txt", "a") as file:
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        file.write(f"{website} | {username} | {encrypted_password} | {now}\n")

    entry_website.delete(0, END)
    entry_username.delete(0, END)
    entry_password.delete(0, END)
    messagebox.showinfo("Saved", "Password saved securely!")

# === View Passwords === #
def view_passwords():
    if not os.path.exists("passwords.txt"):
        messagebox.showinfo("No Data", "No passwords stored yet.")
        return

    output_window = Toplevel(window)
    output_window.title("Saved Passwords")
    output_window.geometry("700x400")

    scrollbar = Scrollbar(output_window)
    scrollbar.pack(side=RIGHT, fill=Y)

    listbox = Listbox(output_window, yscrollcommand=scrollbar.set, width=100)
    listbox.pack(fill=BOTH, expand=True)

    with open("passwords.txt", "r") as file:
        for line in file:
            try:
                site, user, enc_pass, timestamp = line.strip().split(" | ")
                dec_pass = decrypt_password(enc_pass)
                listbox.insert(END, f"Website:: {site} |Username or Email:: {user} |Password:: {dec_pass} | Saved at:: {timestamp}")
            except:
                continue

    scrollbar.config(command=listbox.yview)

# === Delete Password === #
def delete_password():
    website_to_delete = entry_delete.get()
    if not website_to_delete:
        messagebox.showerror("Error", "Enter the website name to delete.")
        return

    if not os.path.exists("passwords.txt"):
        messagebox.showinfo("No Data", "No passwords stored yet.")
        return

    found = False
    with open("passwords.txt", "r") as file:
        lines = file.readlines()

    with open("passwords.txt", "w") as file:
        for line in lines:
            if website_to_delete not in line:
                file.write(line)
            else:
                found = True

    if found:
        messagebox.showinfo("Deleted", f"Password for '{website_to_delete}' deleted.")
    else:
        messagebox.showinfo("Not Found", f"No password found for '{website_to_delete}'.")

    entry_delete.delete(0, END)

# === Emergency Wipe === #
def emergency_wipe():
    if os.path.exists("passwords.txt"):
        os.remove("passwords.txt")
        messagebox.showinfo("Wiped", "All passwords deleted (Emergency Wipe).")
    else:
        messagebox.showinfo("No File", "No password file to delete.")

# === Time-Locked Password View === #
def time_locked_passwords():
    now = datetime.datetime.now().time()
    start = date
    time.time(9, 0)
    end = datetime.time(17, 0)
    if start <= now <= end:
        view_passwords()
    else:
        messagebox.showwarning("Locked", "Passwords can only be viewed between 9 AM and 5 PM.")

# === Password Strength Prediction === #
def password_strength_predictor(password):
    length = len(password)
    score = 0
    if any(c.isdigit() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c in string.punctuation for c in password): score += 1

    if length >= 12 and score == 4:
        return "Very Strong"
    elif length >= 8 and score >= 3:
        return "Strong"
    elif length >= 6 and score >= 2:
        return "Medium"
    else:
        return "Weak"

# === Psychological Password Generator === #
def generate_psychological_password():
    moods = ["Happy", "Creative", "Chill", "Brave", "Focused"]
    inspirations = ["Ocean", "Sky", "Storm", "Lion", "Rocket"]
    random_password = random.choice(moods) + random.choice(inspirations) + str(random.randint(10, 99)) + "!"
    entry_password.delete(0, END)
    entry_password.insert(0, random_password)
    messagebox.showinfo("Generated", f"Password based on your vibe: {random_password}")

# === Update Password by Website === #
def update_password_by_site():
    website = entry_update_site.get()
    new_password = entry_update_new_pass.get()

    if not website or not new_password:
        messagebox.showerror("Error", "Both fields are required.")
        return

    if not os.path.exists("passwords.txt"):
        messagebox.showinfo("No Data", "No stored passwords found.")
        return

    updated = False
    updated_lines = []

    with open("passwords.txt", "r") as file:
        lines = file.readlines()

    for line in lines:
        try:
            site, user, enc_pass, timestamp = line.strip().split(" | ")
            if site == website:
                new_enc_pass = encrypt_password(new_password)
                new_line = f"{site} | {user} | {new_enc_pass} | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                updated_lines.append(new_line)
                updated = True
            else:
                updated_lines.append(line)
        except:
            updated_lines.append(line)

    with open("passwords.txt", "w") as file:
        file.writelines(updated_lines)

    if updated:
        messagebox.showinfo("Updated", f"Password for '{website}' updated successfully.")
    else:
        messagebox.showinfo("Not Found", f"No password found for '{website}'.")

    entry_update_site.delete(0, END)
    entry_update_new_pass.delete(0, END)

# === GUI Layout === #
Label(window, text="Website", font=("Arial", 13,"bold"),  fg="black").pack()
entry_website = Entry(window, width=40, )
entry_website.pack()

Label(window, text="Username/Email:", font=("Arial", 13,"bold"),  fg="black").pack()
entry_username = Entry(window, width=40)
entry_username.pack()

Label(window, text="Password:", font=("Arial", 13,"bold"),  fg="black").pack()
entry_password = Entry(window, width=40, show="*")
entry_password.pack()

Button(window, text="💾 Save Password",font=("Arial", 13,"bold"),  fg="black", command=save_password).pack(pady=5)
Button(window, text="📂 View Passwords",font=("Arial", 13,"bold"),  fg="black", command=view_passwords).pack(pady=5)
Button(window, text="🕒 Time-Locked View (9am-5pm)",font=("Arial", 13,"bold"),  fg="black", command=time_locked_passwords).pack(pady=5)

Label(window, text="Delete by Website:",font=("Arial", 13,"bold"),  fg="black").pack()
entry_delete = Entry(window, width=40)
entry_delete.pack()
Button(window, text="🗑️ Delete Password",font=("Arial", 13,"bold"),  fg="black", command=delete_password).pack(pady=5)

Button(window, text="💥 Emergency Wipe",font=("Arial", 13,"bold"), bg="red", fg="white", command=emergency_wipe).pack(pady=5)
Button(window, text="💡 Psychological Password",font=("Arial", 13,"bold"),  fg="black", command=generate_psychological_password).pack(pady=5)

Button(window, text="🔎 Check Strength",font=("Arial", 13,"bold"),  fg="black", command=lambda: messagebox.showinfo("Strength", password_strength_predictor(entry_password.get()))).pack(pady=5)

# 🔄 Update Password by Website
Label(window, text="Update Password for Website:",font=("Arial", 13,"bold"),  fg="black").pack()
entry_update_site = Entry(window, width=40)
entry_update_site.pack()

Label(window, text="New Password:",font=("Arial", 13,"bold"),  fg="black").pack()
entry_update_new_pass = Entry(window, width=40, show="*")
entry_update_new_pass.pack()

Button(window, text="🔄 Update Password",font=("Arial", 13,"bold"),  fg="black", command=update_password_by_site).pack(pady=5)

# === Mainloop === #
window.mainloop()