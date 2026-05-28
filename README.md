# Red Vault

Red Vault is a secure password manager built with Flask, a native desktop interface, and Argon2 hashing. It allows users to generate, store, and retrieve encrypted passwords while demonstrating secure authentication and cybersecurity best practices.

## Features

- Master password protection
- Argon2 password hashing
- Password generation
- Encrypted password storage
- Flask web interface
- Clipboard support

## Technologies Used

- Python
- Flask
- Argon2
- HTML/CSS
- Pyperclip

## How to Run

Desktop app:

```bash
open dist/RedVault.app
```

Website mode:

```bash
export RED_VAULT_SECRET_KEY="replace-this-with-a-long-random-secret"
/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 app.py --web
```

Then open `http://127.0.0.1:5050` in your browser.

For production, set `RED_VAULT_SECRET_KEY` in your host's environment variables instead of hardcoding it in the repo.

Local phone testing:

```bash
RED_VAULT_HOST=0.0.0.0 /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 app.py --web
```

Find your Mac's Wi-Fi IP address in System Settings, then open `http://YOUR-MAC-IP:5050` on your phone while both devices are on the same Wi-Fi.

## Mobile App Install

Red Vault can be installed as a mobile web app after the website is deployed over HTTPS.

1. Open the deployed Red Vault website on your phone.
2. On iPhone Safari, tap Share, then Add to Home Screen.
3. On Android Chrome, tap the menu, then Install app or Add to Home screen.

The mobile app uses the Red Vault icon, standalone display mode, and mobile-friendly pages.

## Deploy Online

Red Vault includes a `render.yaml` blueprint for deploying the Flask website on Render with HTTPS.

1. Push this repo to GitHub.
2. In Render, create a new Blueprint from the GitHub repo.
3. Render will install `requirements.txt` and run `gunicorn app:app`.
4. Keep the persistent disk enabled at `/var/data` so `vault.db` survives redeploys.
5. Open the Render HTTPS URL on your phone and use Add to Home Screen.

The deployment sets:

- `RED_VAULT_SECRET_KEY` for Flask sessions
- `RED_VAULT_COOKIE_SECURE=1` for HTTPS cookies
- `RED_VAULT_DATA_DIR=/var/data` for persistent SQLite storage

## Web Login

1. Create an account with a username and a password of at least 12 characters.
2. Save website passwords in your private vault.
3. Log out when finished.
4. Log in again later to reveal or copy your previously saved passwords.

Each web account has its own encrypted password records.

## Author

Theo Cseledy
