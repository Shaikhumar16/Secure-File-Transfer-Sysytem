# Secure File Transfer System (AES-GCM) — Ready to Deploy

**Resume summary (copy-paste ready):**
> Built a secure web application for encrypted file uploads using Flask and AES-GCM encryption. Implemented user authentication and activity logging with MySQL and bcrypt. Developed responsive frontend with HTML, CSS, and Bootstrap. Technologies: Python, Flask, MySQL, AES-GCM, bcrypt, HTML, CSS, Bootstrap.

## What you get
- Flask web app that encrypts uploaded files with AES-256-GCM and stores ciphertext on disk
- User registration and login with bcrypt password hashing
- Transfer history (MySQL) and secure downloads (decrypt on download)
- `generate_keys.py` to generate strong keys, `init_admin.py` to create an initial admin user
- Dockerfile + docker-compose.yml (web + mysql)
- `.env.example`, `requirements.txt`, unit tests, GitHub Actions workflow
- Responsive Bootstrap UI

## Quick start (recommended: Docker)
1. Copy `.env.example` to `.env` and fill in values. Generate keys with:
   ```bash
   python generate_keys.py > keys.env
   # copy the AES_KEY and FLASK_SECRET from keys.env into .env
   ```
2. Edit `.env` (set MYSQL_ROOT_PASSWORD, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE, AES_KEY, FLASK_SECRET)
3. Start services:
   ```bash
   docker-compose up --build
   ```
4. Open `http://localhost:5000` and register or run `python init_admin.py` to create an admin account.

## Running locally (no Docker)
1. Create virtualenv and install requirements: `pip install -r requirements.txt`
2. Create a MySQL database and user, or point `.env` to an existing DB.
3. Run `python generate_keys.py` to get AES_KEY and FLASK_SECRET, add to `.env`.
4. Run `python app.py`

## Security notes
- Keep `AES_KEY` and `FLASK_SECRET` secret (use a secrets manager in production)
- AES-GCM requires a unique nonce for each encryption. This app generates a random 12-byte nonce per file and stores it with ciphertext.
- Do not change AES_KEY after files have been uploaded (you will not be able to decrypt them).

## Files of interest
- `app.py` — main Flask app
- `generate_keys.py` — prints strong AES key and Flask secret
- `init_admin.py` — create admin user directly in DB
- `db_setup.sql` — schema for `users` and `transfers`
- `docker-compose.yml`, `Dockerfile`
- `templates/` — HTML templates (Bootstrap)
