import argparse
import base64
import json
import os
import sys
import getpass
import secrets
import datetime
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Optional
from typing import Tuple
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

USERS_FILE = "users.json"
TOKENS_FILE = "tokens.json"
TASKS_DIR = "tasks"
LOG_KEY_FILE = "log_key.bin"
AUDIT_LOG_FILE = "audit_log.bin"

KDF_ITERATIONS = 200_000
SALT_SIZE = 16
AES_KEY_SIZE = 32
NONCE_SIZE = 12

def ensure_dirs():
    os.makedirs(TASKS_DIR, exist_ok=True)

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

@dataclass
class Task:
    id: str
    due_date: str
    description: Optional[str] = None
    classification: Optional[str] = None
    ciphertext: Optional[str] = None
    nonce: Optional[str] = None

@dataclass
class UserRecord:
    agent_id: str
    username: str
    password_hash: str
    salt: str
    authorization_level: int = 1

def load_users() -> List[UserRecord]:
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r") as f:
        data = json.load(f)
    return [UserRecord(**u) for u in data]

def save_users(users: List[UserRecord]):
    with open(USERS_FILE, "w") as f:
        json.dump([asdict(u) for u in users], f, indent=2)

def user_by_username(username: str) -> Optional[UserRecord]:
    for u in load_users():
        if u.username == username:
            return u
    return None

def user_by_agent(agent_id: str) -> Optional[UserRecord]:
    for u in load_users():
        if u.agent_id == agent_id:
            return u
    return None

def tasks_file_for(agent_id: str) -> str:
    return os.path.join(TASKS_DIR, f"{agent_id}.json")

def load_tasks(agent_id: str) -> List[Task]:
    path = tasks_file_for(agent_id)
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        data = json.load(f)
    tasks = []
    for t in data:
        tasks.append(Task(**t))
    return tasks

def save_tasks(agent_id: str, tasks: List[Task]):
    path = tasks_file_for(agent_id)
    with open(path, "w") as f:
        json.dump([asdict(t) for t in tasks], f, indent=2)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt_sensitive_fields(key: bytes, description: str, classification: str) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    payload = json.dumps({"description": description, "classification": classification}).encode()
    ct = aesgcm.encrypt(nonce, payload, associated_data=None)
    return nonce, ct

def decrypt_sensitive_fields(key: bytes, nonce: bytes, ciphertext: bytes) -> dict:
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(pt.decode())

def get_or_create_log_key() -> bytes:
    if os.path.exists(LOG_KEY_FILE):
        return open(LOG_KEY_FILE, "rb").read()
    key = os.urandom(AES_KEY_SIZE)
    with open(LOG_KEY_FILE, "wb") as f:
        f.write(key)
    return key

def append_audit(entry: str):
    key = get_or_create_log_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    payload = json.dumps({"ts": timestamp, "entry": entry}).encode()
    ct = aesgcm.encrypt(nonce, payload, associated_data=None)
    out = {"nonce": b64(nonce), "ct": b64(ct)}
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r+") as f:
            try:
                data = json.load(f)
            except Exception:
                data = []
            data.append(out)
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
    else:
        with open(AUDIT_LOG_FILE, "w") as f:
            json.dump([out], f, indent=2)

def load_tokens() -> List[str]:
    if not os.path.exists(TOKENS_FILE):
        return []
    with open(TOKENS_FILE, "r") as f:
        return json.load(f)

def save_tokens(tokens: List[str]):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f)

def issue_token_for_agent(agent_id: str) -> str:
    token = secrets.token_urlsafe(16)
    tokens = load_tokens()
    tokens.append(token)
    save_tokens(tokens)
    append_audit(f"Issued token for agent {agent_id}")
    return token

def consume_token(token: str) -> bool:
    tokens = load_tokens()
    if token in tokens:
        tokens.remove(token)
        save_tokens(tokens)
        append_audit(f"Token consumed: {token}")
        return True
    return False

# --- operations ---
def register(args):
    ensure_dirs()
    agent_id = input("Agent ID (provided by agency): ").strip()
    if not agent_id:
        print("Agent ID is required.")
        return
    if user_by_agent(agent_id):
        print("Agent ID already exists.")
        return
    username = input("Username: ").strip()
    if user_by_username(username):
        print("Username already taken.")
        return
    password = getpass.getpass("Password: ")
    password2 = getpass.getpass("Confirm password: ")
    if password != password2:
        print("Passwords do not match.")
        return
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    salt = os.urandom(SALT_SIZE)
    u = UserRecord(agent_id=agent_id, username=username, password_hash=pw_hash, salt=b64(salt), authorization_level=1)
    users = load_users()
    users.append(u)
    save_users(users)
    print("Account created successfully.\n")
    append_audit(f"Registered agent {agent_id} ({username})")

def login_prompt() -> Optional[UserRecord]:
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    u = user_by_username(username)
    if not u:
        print("No such user.")
        return None
    if bcrypt.checkpw(password.encode(), u.password_hash.encode()):
        print("Login successful.")
        append_audit(f"Login success for {u.agent_id}")
        return u
    else:
        print("Login failed.")
        append_audit(f"Login failed for {u.agent_id}")
        return None

def add_task(args):
    u = login_prompt()
    if not u:
        return
    password = getpass.getpass("Password (used to derive encryption key): ")
    if not bcrypt.checkpw(password.encode(), u.password_hash.encode()):
        print("Password verification failed.")
        return
    salt = ub64(u.salt)
    key = derive_key(password, salt)
    description = input("Task description: ")
    due_date = input("Due date (YYYY-MM-DD): ")
    classification = input("Classification (Top Secret/Secret/Confidential): ")
    tid = secrets.token_hex(8)
    nonce, ct = encrypt_sensitive_fields(key, description, classification)
    task = Task(id=tid, due_date=due_date, ciphertext=b64(ct), nonce=b64(nonce))
    tasks = load_tasks(u.agent_id)
    tasks.append(task)
    save_tasks(u.agent_id, tasks)
    print(f"Task added (id={tid}). Sensitive fields encrypted.")
    append_audit(f"Agent {u.agent_id} added task {tid}")

def list_tasks(args):
    u = login_prompt()
    if not u:
        return
    tasks = load_tasks(u.agent_id)
    if not tasks:
        print("No tasks.")
        return
    print(f"Tasks for {u.agent_id} (sensitive fields redacted):")
    for t in tasks:
        print(f"- id: {t.id} | due: {t.due_date} | description: [REDACTED] | classification: [REDACTED]")

def view_task(args):
    u = login_prompt()
    if not u:
        return
    task_id = input("Task ID to view (decrypt): ")
    tasks = load_tasks(u.agent_id)
    found = None
    for t in tasks:
        if t.id == task_id:
            found = t
            break
    if not found:
        print("Task not found.")
        return
    token = getpass.getpass("Agency one-time token: ")
    if not consume_token(token):
        print("Invalid or expired token. Cannot decrypt sensitive fields.")
        append_audit(f"Failed token attempt for {u.agent_id} viewing {task_id}")
        return
    password = getpass.getpass("Password (to derive key): ")
    if not bcrypt.checkpw(password.encode(), u.password_hash.encode()):
        print("Password verification failed.")
        return
    key = derive_key(password, ub64(u.salt))
    try:
        dec = decrypt_sensitive_fields(key, ub64(found.nonce), ub64(found.ciphertext))
    except Exception:
        print("Decryption failed: wrong key or corrupted data.")
        append_audit(f"Decryption failure for {u.agent_id} task {task_id}")
        return
    print("Decrypted task details:")
    print(f"- id: {found.id}")
    print(f"- due_date: {found.due_date}")
    print(f"- description: {dec['description']}")
    print(f"- classification: {dec['classification']}")
    append_audit(f"Agent {u.agent_id} decrypted task {task_id}")

def request_token(args):
    agent_id = input("Agent ID to issue token for: ")
    if not user_by_agent(agent_id):
        print("Unknown agent ID.")
        return
    token = issue_token_for_agent(agent_id)
    print("*** AGENT TOKEN (SIMULATION) ***")
    print(token)
    print("(This is a simulated one-time token. In production, the agency would provide this through a secure channel.)")

def reset_password(args):
    agent_id = input("Agent ID: ")
    u = user_by_agent(agent_id)
    if not u:
        print("Unknown agent.")
        return
    token = getpass.getpass("Agency one-time token authorising reset: ")
    if not consume_token(token):
        print("Invalid or expired token.")
        return
    newpw = getpass.getpass("New password: ")
    newpw2 = getpass.getpass("Confirm new password: ")
    if newpw != newpw2:
        print("Passwords do not match.")
        return
    new_hash = bcrypt.hashpw(newpw.encode(), bcrypt.gensalt()).decode()
    users = load_users()
    for i, r in enumerate(users):
        if r.agent_id == agent_id:
            users[i].password_hash = new_hash
            break
    save_users(users)
    print("Password reset complete. NOTE: existing encrypted tasks will remain encrypted with previous derived key."
          " You should re-encrypt tasks or contact admin to rewrap keys.")
    append_audit(f"Password reset for {agent_id}")

def main():
    parser = argparse.ArgumentParser(description="Secure Task Manager (demo)")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("register", help="Register a new agent account")
    sub.add_parser("login", help="Login (interactive prompt)")
    sub.add_parser("add-task", help="Add a new encrypted task")
    sub.add_parser("list-tasks", help="List tasks (sensitive fields redacted)")
    sub.add_parser("view-task", help="View (decrypt) a task - requires agency one-time token")
    sub.add_parser("request-token", help="(SIM) Request a one-time token from agency")
    sub.add_parser("reset-password", help="Reset password with agency token")

    args = parser.parse_args()
    if args.cmd == "register":
        register(args)
    elif args.cmd == "login":
        u = login_prompt()
        if u:
            print(f"Welcome, {u.username} (agent: {u.agent_id})")
    elif args.cmd == "add-task":
        add_task(args)
    elif args.cmd == "list-tasks":
        list_tasks(args)
    elif args.cmd == "view-task":
        view_task(args)
    elif args.cmd == "request-token":
        request_token(args)
    elif args.cmd == "reset-password":
        reset_password(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
