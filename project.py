import argparse
import getpass
import os
import json
import bcrypt
import base64
import uuid
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from datetime import datetime

USERS_DIR = "users"
TASKS_DIR = "tasks"

os.makedirs(USERS_DIR, exist_ok=True)
os.makedirs(TASKS_DIR, exist_ok=True)

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_data(data: str, fernet: Fernet) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(token: str, fernet: Fernet) -> str:
    return fernet.decrypt(token.encode()).decode()

class User:
    def __init__(self, agent_id, username, password_hash, salt, auth_level):
        self.agent_id = agent_id
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.auth_level = auth_level  # e.g., "Admin", "Agent"

    def save(self):
        with open(f"{USERS_DIR}/{self.username}.json", "w") as f:
            json.dump(self.__dict__, f)

    @staticmethod
    def load(username):
        try:
            with open(f"{USERS_DIR}/{username}.json", "r") as f:
                data = json.load(f)
                return User(**data)
        except FileNotFoundError:
            return None

def register():
    username = input("Username: ").strip()
    agent_id = input("Agent ID: ").strip()

    if os.path.exists(f"{USERS_DIR}/{username}.json"):
        print("Username already exists.")
        return

    password = getpass.getpass("Password: ")
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    salt = os.urandom(16)
    auth_level = "Agent"  # Default, can be "Admin"

    user = User(agent_id, username, password_hash, base64.b64encode(salt).decode(), auth_level)
    user.save()
    print("Account created successfully.")

def login():
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    user = User.load(username)
    if not user:
        print("User not found.")
        return None

    if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        print("Invalid credentials.")
        return None

    key = derive_key(password.encode(), base64.b64decode(user.salt))
    print("Login successful!")
    return user, Fernet(key)

def add_task(user, fernet):
    description = input("Task Description: ")
    due_date = input("Due Date (YYYY-MM-DD): ")
    classification = input("Classification (Top Secret / Secret / Confidential): ")

    task = {
        "id": str(uuid.uuid4()),
        "due_date": due_date,
        "description": encrypt_data(description, fernet),
        "classification": encrypt_data(classification, fernet),
    }

    filepath = f"{TASKS_DIR}/{user.username}_tasks.json"
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            tasks = json.load(f)
    else:
        tasks = []

    tasks.append(task)

    with open(filepath, "w") as f:
        json.dump(tasks, f, indent=2)

    print("Task added successfully.")

def view_tasks(user):
    filepath = f"{TASKS_DIR}/{user.username}_tasks.json"
    if not os.path.exists(filepath):
        print("No tasks found.")
        return

    with open(filepath, "r") as f:
        tasks = json.load(f)

    for i, task in enumerate(tasks, 1):
        print(f"\nTask {i}")
        print(f"ID: {task['id']}")
        print(f"Due Date: {task['due_date']}")
        print("Description: [REDACTED]")
        print("Classification: [REDACTED]")

def decrypt_task(user, fernet):
    filepath = f"{TASKS_DIR}/{user.username}_tasks.json"
    if not os.path.exists(filepath):
        print("No tasks found.")
        return

    token = input("Enter secure token from agency: ").strip()
    if token != "123456":  # Example only. Replace with secure token validation.
        print("Invalid token.")
        return

    with open(filepath, "r") as f:
        tasks = json.load(f)

    for i, task in enumerate(tasks, 1):
        print(f"\nTask {i}")
        print(f"ID: {task['id']}")
        print(f"Due Date: {task['due_date']}")
        print("Description:", decrypt_data(task["description"], fernet))
        print("Classification:", decrypt_data(task["classification"], fernet))

def main():
    parser = argparse.ArgumentParser(description="Secure Task Manager")
    parser.add_argument("command", choices=["register", "login", "add_task", "view_tasks", "decrypt_task"])

    args = parser.parse_args()

    if args.command == "register":
        register()
    elif args.command == "login":
        user_data = login()
        if user_data:
            user, fernet = user_data
    else:
        user_data = login()
        if user_data:
            user, fernet = user_data
            if args.command == "add_task":
                add_task(user, fernet)
            elif args.command == "view_tasks":
                view_tasks(user)
            elif args.command == "decrypt_task":
                decrypt_task(user, fernet)

if __name__ == "__main__":
    main()
