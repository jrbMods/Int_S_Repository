import requests
import hashlib
import random
import string
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from io import BytesIO
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import torch

# -------------------- Load AI Model --------------------
print("Loading AI model...")
model_name = "gpt2"
tokenizer = GPT2Tokenizer.from_pretrained(model_name)
model = GPT2LMHeadModel.from_pretrained(model_name)

# -------------------- Load Logo from ImgBB --------------------
def load_logo():
    try:
        img_url = "https://i.ibb.co/B2jTDTxs/jrbbeta.png"  # Replace with your ImgBB link
        response = requests.get(img_url)
        image = Image.open(BytesIO(response.content))
        image = image.resize((80, 30))  # Resize
        logo_img = ImageTk.PhotoImage(image)
        
        logo_label.config(image=logo_img)
        logo_label.image = logo_img  # Keep reference to avoid garbage collection
    except Exception as e:
        print("Error loading logo:", e)

# -------------------- Password Check Function --------------------
def check_password_pwned(password):
    """Checks if a password exists in the Have I Been Pwned database."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    first5, tail = sha1_hash[:5], sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)

    if tail in response.text:
        return True  # Password is compromised
    return False  # Password is safe

# -------------------- AI-Powered Password Suggestion --------------------
def ai_suggest_password(password):
    """Uses AI (GPT-2) to suggest a more secure password."""
    input_text = f"Improve this password: {password}\nNew password:"
    inputs = tokenizer.encode(input_text, return_tensors="pt")

    with torch.no_grad():
        outputs = model.generate(inputs, max_length=30, num_return_sequences=1, pad_token_id=50256)

    ai_password = tokenizer.decode(outputs[0], skip_special_tokens=True).split("\nNew password:")[-1].strip()

    if len(ai_password) < 8:
        return suggest_improvement(password)  # Fallback to manual suggestion if AI fails

    return ai_password

# -------------------- Password Suggestion Function --------------------
def suggest_improvement(password):
    """Suggests a stronger, uncompromised password"""
    while True:
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        new_password = password + random_suffix

        if not check_password_pwned(new_password):
            return new_password

# -------------------- Secure Password Generator --------------------
def generate_secure_password():
    """Generates a strong, random password and ensures it's not compromised"""
    while True:
        password_length = 12
        new_password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=password_length))

        if not check_password_pwned(new_password):
            suggested_label.config(text=f"✅ AI Generated Password: {new_password}", fg="blue")
            return

# -------------------- GUI Functions --------------------
def check_password():
    """Checks if the entered password is secure"""
    password = password_entry.get().strip()

    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return

    if check_password_pwned(password):
        result_label.config(text="⚠️ Compromised! Suggesting a better password...", fg="red")
        secure_password = ai_suggest_password(password)
        suggested_label.config(text=f"✅ AI Suggested Password: {secure_password}", fg="green")
    else:
        result_label.config(text="✅ Safe Password!", fg="green")
        suggested_label.config(text="")

def save_password():
    """Saves the suggested or generated password to a file"""
    suggested_password = suggested_label.cget("text").replace("✅ AI Suggested Password: ", "").replace("✅ AI Generated Password: ", "").strip()

    if not suggested_password:
        messagebox.showerror("Error", "No password to save!")
        return

    with open("saved_passwords.txt", "a") as file:
        file.write(suggested_password + "\n")

    messagebox.showinfo("Success", "Password saved successfully!")

# -------------------- GUI Setup --------------------
root = tk.Tk()
root.title("AI-Powered Password Checker")
root.geometry("450x450")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)
password_entry = tk.Entry(root, show="*", font=("Arial", 12))
password_entry.pack(pady=5)

check_button = tk.Button(root, text="Check Password", command=check_password, font=("Arial", 12))
check_button.pack(pady=10)

generate_button = tk.Button(root, text="Generate Secure Password", command=generate_secure_password, font=("Arial", 12))
generate_button.pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=5)

suggested_label = tk.Label(root, text="", font=("Arial", 12))
suggested_label.pack(pady=5)

save_button = tk.Button(root, text="Save Password", command=save_password, font=("Arial", 12))
save_button.pack(pady=10)

# -------------------- Logo Placement --------------------
logo_label = tk.Label(root)
logo_label.pack(side="bottom", pady=10)
load_logo()
# -------------------- Text Below the Logo --------------------
text_label = tk.Label(root, text="© 2025 TU-Sofia / Grigorios K. Makris / 273221010", font=("Arial", 10), fg="gray")
text_label.pack(side="bottom", pady=5)

root.mainloop()
