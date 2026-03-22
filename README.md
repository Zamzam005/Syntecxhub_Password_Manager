Password Manager

A command line password manager built in Python. 
All passwords are encrypted with AES-256-GCM and saved to a local file on your computer.
Nothing is sent to any server.

What it does

•	Add credentials (site, username, password)
•	List all saved entries
•	Search by site or username
•	Delete entries
•	Generate strong random passwords
•	Password strength checker

How the encryption works

When you set a master password, it gets turned into a 32-byte encryption key using PBKDF2. 
PBKDF2 runs the hashing 390,000 times on purpose — this makes it very slow for anyone trying to guess your password by brute force.
All your credentials are then encrypted with AES-256-GCM and saved to a file called vault.enc. 
Without the master password, the file is unreadable.

How to run it

Install the one dependency:

pip install cryptography

Run the program:

python password_manager.py

First time running it will ask you to create a master password. 
After that it will ask for your master password every time to unlock the vault.

Files

•	password_manager.py — the main program
•	vault.enc — created automatically when you first run it (your encrypted data)

Important

If you forget your master password your data cannot be recovered.
This is by design — that is what makes it secure.
Do not upload vault.enc to GitHub.

Built with

•	Python 3
•	cryptography library (AES-256-GCM, PBKDF2)

Internship

Built as part of the Syntecxhub Internship Program.
