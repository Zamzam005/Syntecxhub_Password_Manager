# Password Manager
# Author: Zamzam Hassan

import os
import json
import base64
import secrets
import string
import getpass
import re
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

VAULT_FILE = Path("vault.enc")


def derive_key(password, salt):
    # PBKDF2 runs 390,000 times to slow down brute force attacks
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(password.encode())


def encrypt_vault(plaintext, password):
    # fresh salt and nonce every save so the output is never the same
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    key   = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        "salt":  base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data":  base64.b64encode(ciphertext).decode(),
    }


def decrypt_vault(blob, password):
    try:
        salt       = base64.b64decode(blob["salt"])
        nonce      = base64.b64decode(blob["nonce"])
        ciphertext = base64.b64decode(blob["data"])
        key        = derive_key(password, salt)
        aesgcm     = AESGCM(key)
        plaintext  = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        raise ValueError("Wrong master password or corrupted vault.")


def save_vault(entries, password):
    payload = json.dumps({"entries": entries, "saved_at": datetime.now().isoformat()})
    blob = encrypt_vault(payload, password)
    VAULT_FILE.write_text(json.dumps(blob, indent=2))


def load_vault(password):
    if not VAULT_FILE.exists():
        return []
    blob = json.loads(VAULT_FILE.read_text())
    payload = json.loads(decrypt_vault(blob, password))
    return payload.get("entries", [])


def generate_password(length=20):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    # guarantee at least one of each character type
    pwd = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def score_password(pw):
    score = 0
    if len(pw) >= 8:  score += 1
    if len(pw) >= 14: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"[0-9]", pw): score += 1
    if re.search(r"[^A-Za-z0-9]", pw): score += 1
    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"}
    return score, labels[score]


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print("\n" + "=" * 50)
    print("       Password Manager")
    print("=" * 50)


def list_entries(entries):
    if not entries:
        print("\nNo entries yet.")
        return
    print(f"\n{len(entries)} entry/entries in vault:\n")
    for e in entries:
        print(f"  [{e['id']}]  {e['site']}  |  {e['username']}")


def view_entry(entries):
    list_entries(entries)
    if not entries:
        return
    entry_id = input("\nEnter ID to view (or Enter to cancel): ").strip()
    if not entry_id:
        return
    match = next((e for e in entries if e["id"] == entry_id), None)
    if not match:
        print("ID not found.")
        return
    print(f"\n  Site     : {match['site']}")
    print(f"  Username : {match['username']}")
    print(f"  Password : {match['password']}")
    if match.get("notes"):
        print(f"  Notes    : {match['notes']}")


def add_entry(entries, master):
    print("\n[ Add Entry ]")
    site     = input("Site or app: ")
    username = input("Username or email: ")
    choice   = input("Generate password? (y/n): ").strip().lower()

    if choice == "y":
        pw = generate_password()
        print("Generated: " + pw)
    else:
        pw = getpass.getpass("Enter password: ")
        score, label = score_password(pw)
        print("Strength: " + label)

    notes = input("Notes (optional): ").strip()

    entry = {
        "id":       secrets.token_hex(4),
        "site":     site.strip(),
        "username": username.strip(),
        "password": pw,
        "notes":    notes,
        "created":  datetime.now().isoformat(),
    }
    entries.append(entry)
    save_vault(entries, master)
    print("Entry saved!")
    return entries


def search_entries(entries):
    print("\n[ Search ]")
    query = input("Search: ").lower()
    found = [e for e in entries if query in e["site"].lower() or query in e["username"].lower()]

    if not found:
        print("Nothing found.")
    else:
        for e in found:
            print(f"  [{e['id']}]  {e['site']}  |  {e['username']}")


def delete_entry(entries, master):
    list_entries(entries)
    if not entries:
        return entries

    entry_id = input("\nEnter ID to delete (or Enter to cancel): ").strip()
    if not entry_id:
        return entries

    match = next((e for e in entries if e["id"] == entry_id), None)
    if not match:
        print("ID not found.")
        return entries

    confirm = input(f"Delete '{match['site']}'? (yes/n): ")
    if confirm.lower() != "yes":
        print("Cancelled.")
        return entries

    entries = [e for e in entries if e["id"] != entry_id]
    save_vault(entries, master)
    print("Deleted.")
    return entries


def action_generate():
    try:
        length = int(input("Password length (default 20): ") or "20")
        length = max(8, min(64, length))
    except ValueError:
        length = 20
    pw = generate_password(length)
    score, label = score_password(pw)
    print(f"\nGenerated : {pw}")
    print(f"Strength  : {label}")


def login():
    banner()

    if VAULT_FILE.exists():
        print("Vault found. Enter your master password.")
        attempts = 0
        while attempts < 3:
            master = getpass.getpass("Master password: ")
            try:
                entries = load_vault(master)
                print("Vault unlocked!")
                return master, entries
            except ValueError:
                attempts += 1
                remaining = 3 - attempts
                if remaining:
                    print(f"Wrong password. {remaining} attempt(s) left.")
                else:
                    print("Too many failed attempts. Exiting.")
                    exit()
    else:
        print("No vault found. Creating one.")
        while True:
            master = getpass.getpass("Choose master password (min 8 chars): ")
            if len(master) < 8:
                print("Too short, try again.")
                continue
            score, label = score_password(master)
            print("Strength: " + label)
            confirm = getpass.getpass("Confirm password: ")
            if master != confirm:
                print("Passwords don't match, try again.")
                continue
            break
        entries = []
        save_vault(entries, master)
        print("Vault created!")
        return master, entries


def main():
    master, entries = login()

    while True:
        print(f"\n{'=' * 50}")
        print(f"  Vault unlocked  |  {len(entries)} entries")
        print(f"{'=' * 50}")
        print("  [1] List entries")
        print("  [2] View entry")
        print("  [3] Add entry")
        print("  [4] Search")
        print("  [5] Delete entry")
        print("  [6] Generate password")
        print("  [0] Exit")
        print(f"{'=' * 50}")

        choice = input("Choose: ").strip()

        if choice == "1":
            list_entries(entries)
        elif choice == "2":
            view_entry(entries)
        elif choice == "3":
            entries = add_entry(entries, master)
        elif choice == "4":
            search_entries(entries)
        elif choice == "5":
            entries = delete_entry(entries, master)
        elif choice == "6":
            action_generate()
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Type 0-6")

        input("\nPress Enter to continue...")
        clear()
        banner()


if __name__ == "__main__":
    main()