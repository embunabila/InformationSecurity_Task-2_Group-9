# Medimo: Personal Health Record

**Group 9 | Information Security (I)**

## Team Members

| No. | Student Name | Student ID |
|---:|---|---|
| 1 | Adelia Tanalina Yumna | 5025241078 |
| 2 | Almira Nayla Felisitha | 5025241014 |
| 3 | Embun Nabila Azzahra Rasendrya | 5025241009 |
| 4 | Nuha Usama Okbah | 5025241005 |

**Lecturer:** Dr. Baskoro Adi Pratomo, S.Kom., M.Kom., Ph.D.

**Course:** Information Security

---

## Project Overview

Medimo is a web-based Personal Health Record (PHR) application that allows users to securely store and manage their personal health information in one place. It is designed for people who need convenient access to their medical records, such as laboratory results, prescriptions, identity documents, and symptom videos during medical consultations.

Assignment 1 demonstrates authentication, data ownership, encryption at rest, and integrity verification using AES, DES, and RC4.

Assignment 2 adds **secure data sharing between users**. A patient often needs someone else, such as a family member who accompanies them to a consultation, to see part of their records. Medimo lets a user request another user's data, lets the owner decide exactly what to share and for how long, and delivers the sharing key outside the application protected with asymmetric encryption.

## Features

- **User authentication:** Register, log in, and log out securely.
- **Health profile management:** Create and update personal health information, including date of birth, gender, contact information, allergies, health conditions, and routine medication.
- **Medical file management:** Upload, retrieve, download, and delete personal files.
- **Encryption at rest:** Store three independent encrypted copies of each supported record using AES, DES, and RC4.
- **Integrity verification:** Use HMAC-SHA256 to detect tampering before decryption.
- **Ownership enforcement:** Restrict access to records belonging to the authenticated user.
- **Upload size limits:** Support uploads with a maximum file size of 25 MiB.
- **CSRF protection:** Protect state-changing requests against cross-site request forgery.

### Data Sharing (Assignment 2)

- **Key pairs:** Each user creates an RSA-3072 key pair on the **My keys** page and can copy its fingerprint.
- **Access requests:** A user asks another user for one category of data (health profile, identity, document, or video) and gives a reason.
- **Owner-controlled approval:** The owner chooses the exact files or profile fields to share and an access period of 1, 7, or 30 days, or rejects the request.
- **Key package:** On approval, a new symmetric key encrypts a copy of the selected data. The key is wrapped with the requester's public key and given to the owner as a key package to send by WhatsApp or email.
- **Opening shared data:** The requester pastes the key package and enters their password to view or download the shared items. Shared profiles are shown as a table.
- **Revocation and expiry:** The owner can revoke access at any time, and access ends automatically after the chosen period.
- **Audit log:** Requests, approvals, rejections, openings, revocations, and expiries are recorded without any sensitive data.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript, Jinja |
| Database | SQLite |
| Cryptography | PyCryptodome |
| Password security | Werkzeug password hashing |
| Key derivation | HKDF-SHA256 |
| Integrity verification | HMAC-SHA256 |
| Asymmetric encryption | RSA-3072 with OAEP-SHA256 |
| Private key protection | scrypt (N=2^17, r=8, p=1) |

## Encryption Design

Medimo uses three independent encrypted copies of each supported record to compare the processing cost and storage overhead of AES, DES, and RC4.

The three copies are **not layered encryption**. Each algorithm independently encrypts the same original data.

| Algorithm | Construction | Purpose |
|---|---|---|
| AES | AES-256-CBC with PKCS#7 padding | Primary algorithm for retrieving records |
| DES | DES-CBC with PKCS#7 padding | Legacy algorithm for comparison |
| RC4 | RC4 stream cipher | Legacy algorithm for comparison |

All three constructions use HMAC-SHA256 for integrity verification. AES and DES use fresh random initialization vectors (IVs), while RC4 does not require an IV or block padding.

A persistent 32-byte master key is loaded from the environment. HKDF-SHA256 derives separate encryption and authentication keys using random salts and algorithm-specific labels.

The encrypted envelopes include format information and authenticate the relevant header, record context, and ciphertext. The backend supplies the expected owner and item context during decryption to help prevent encrypted records from being substituted across users or items.

Authentication and ownership checks remain necessary even when cryptographic verification is enabled.

## Data Sharing Design

| Part | Design |
|---|---|
| User key pair | RSA-3072. The public key and its SHA-256 fingerprint are stored as-is. The private key is encrypted with a key derived from the user's login password using scrypt and a random 16-byte salt. |
| Share key | A fresh random 32-byte key for every approved request, independent of the master key. |
| Shared data | The selected items are copied and the copies are encrypted with the share key using the same AES-256-CBC + HMAC-SHA256 envelope, bound to the owner and the copy's ID. |
| Key storage | Only the share key wrapped with the requester's public key (RSA-OAEP, with the request ID as the OAEP label) is stored. The plain share key is never written to disk, the database, the session, or logs. |
| Key delivery | The owner checks the requester's fingerprint against the value the requester sends through another channel, then sends the key package (`MEDIMO-KEY-1:` + base64url) by WhatsApp or email. |
| Opening data | The requester enters the package and password each time. Keys exist only in memory for that request. |
| Ending access | Revoking or expiring deletes the shared copies and the wrapped key, so an old package no longer opens anything. |
| Abuse limits | Five failed password attempts lock the private key for 15 minutes. Error messages are generic. |

Login passwords are hashed with scrypt using the same parameters as the private-key protection, so the login hash is not a cheaper way to guess a user's password.

## Security Considerations and Limitations

Medimo is an academic prototype, not a production-ready medical records platform.

- **DES and RC4 are insecure legacy algorithms.** They are included to satisfy the assignment's comparison requirements, not recommended for protecting real medical data.
- **The application is not end-to-end encrypted.** The server holds the master key and can decrypt records.
- **Master key loss prevents recovery** of records encrypted with that key. Changing the key without a proper migration process also makes existing records inaccessible.
- **Storage overhead increases** because each record has three independent encrypted copies.
- **File processing uses memory.** Large uploads may require substantial memory because payloads and multiple encrypted copies are processed.
- **Rollback protection is limited.** Integrity verification detects unauthorized modifications but does not independently prevent an older, previously valid version of a record from being restored.
- **The prototype has limited deployment hardening.** It should not be used with real patient information or exposed publicly without further security review and testing.
- **Shared data that was already downloaded cannot be recalled.** Revoking access removes the stored copies, but not files the requester has saved.
- **Fingerprint checking depends on users.** It only detects a substituted public key if the owner compares it with the value the requester sends separately.
- **A forgotten password cannot be recovered.** The private key is protected by the login password, so the user must create a new key pair and request access again.
- **A compromised running server is not protected against.** The server briefly holds the share key during approval and receives passwords.

Use dummy data when running or demonstrating this project.

## Getting Started

### Prerequisites

- Python 3.12 or a compatible Python version
- Git
- PowerShell on Windows, or an equivalent terminal on other operating systems

### 1. Clone the Repository

```bash
git clone https://github.com/embunabila/InformationSecurity_Task-2_Group-9.git
cd InformationSecurity_Task-2_Group-9
```

### 2. Create and Activate a Virtual Environment

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, you can allow activation scripts for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Initialize the Database

```powershell
python db.py
```

Run this again after deleting `medimo.db`; otherwise registering or logging in fails because the tables do not exist.

### 5. Configure the Environment Variables

Generate a persistent Flask session secret and master key for local development:

```powershell
python -c "import secrets; from pathlib import Path; p=Path('.env.local'); p.write_text('SECRET_KEY='+secrets.token_hex(32)+'\nMASTER_KEY='+secrets.token_hex(32)+'\n', encoding='utf-8') if not p.exists() else print('Keys already exist; keeping the existing file.')"
```

Load the variables into the current PowerShell session:

```powershell
Get-Content .env.local | ForEach-Object {
    $name, $value = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
}
```

**Important:**

- Keep `.env.local` private and never commit it to GitHub.
- Keep the same master key when reopening existing encrypted records.
- Do not regenerate the key if you need to access previously stored data.
- Store the keys securely and ensure `.env.local` is excluded from version control.

### 6. Run the Application

```powershell
python app.py
```

Open the application in your browser:

[http://127.0.0.1:5000](http://127.0.0.1:5000)

Register an account, log in, and use dummy information to explore the application.

### Trying the Data Sharing Feature

Use two accounts at the same time, for example one in a normal browser window (the owner) and one in a private/incognito window (the requester).

1. Register both accounts, then create a key pair on **My keys** in each one. Note the requester's fingerprint.
2. As the owner, upload a dummy file on the dashboard.
3. As the requester, open **Access requests**, enter the owner's username, choose the same category, and send the request.
4. As the owner, open **Access requests**, select the file and an access period, and approve.
5. As the owner, click **Get key package**, check that the fingerprint matches the requester's, then copy or download the package.
6. As the requester, open **Shared with me**, paste the package, enter the password, and view or download the file.
7. As the owner, click **Revoke access**. The requester can no longer open the item.

## Running Tests

Run the test suite from the project root:

```powershell
python -m unittest discover -s tests -v
```

The tests cover cryptographic operations, envelope validation, integrity verification, file payload handling, and selected application behaviors.

For data sharing, they also cover key pair generation and locking, key wrapping, the key package format, request approval and rejection, access checks, revocation, expiry, and an end-to-end test with real accounts in `tests/test_share_integration.py`.

## Project Structure

```text
InformationSecurity_Task-2_Group-9/
├── app.py                 # Flask routes and application logic
├── config.py              # Master key configuration
├── crypto_core.py         # AES, DES, RC4, and integrity verification
├── crypto_tool.py         # Standalone cryptography utility
├── db.py                  # SQLite database operations
├── file_payload.py        # File metadata and payload handling
├── storage.py             # Private encrypted file storage
├── user_keys.py           # RSA key pairs, private key protection, key wrapping
├── share_keys.py          # Share keys, encrypted share copies, key packages
├── share_requests.py      # Access requests, approval, access checks, audit log
├── share_access.py        # Opening shared items, revocation, expiry
├── keys_routes.py         # My keys page
├── request_routes.py      # Access requests page
├── grant_routes.py        # Key package page and download
├── access_routes.py       # Shared with me page and revocation
├── web_utils.py           # Shared login and CSRF helpers
├── share_errors.py        # Shared error classes for data sharing
├── templates/             # HTML/Jinja templates
├── static/                # CSS and JavaScript assets
├── tests/                 # Automated tests
├── docs/                  # Project design and cryptography contract
├── requirements.txt       # Python dependencies
└── README.md
```

## Project Scope

Medimo uses a single application role: the user. Any user can share their own records with another registered user through access requests. Doctor accounts, administrator roles, and public sharing links are outside the current scope.

The project focuses on demonstrating secure data handling, cryptographic integrity, ownership checks, the practical trade-offs between different encryption algorithms, and secure key management for sharing data between users.

## Academic Context

This project was developed by **Group 9** for the **Information Security (I)** course.

**Lecturer:** Dr. Baskoro Adi Pratomo, S.Kom., M.Kom., Ph.D.

### Team Members

| No. | Student Name | Student ID |
|---:|---|---|
| 1 | Adelia Tanalina Yumna | 5025241078 |
| 2 | Almira Nayla Felisitha | 5025241014 |
| 3 | Embun Nabila Azzahra Rasendrya | 5025241009 |
| 4 | Nuha Usama Okbah | 5025241005 |

**Repository:** [InformationSecurity_Task-2_Group-9](https://github.com/embunabila/InformationSecurity_Task-2_Group-9)

**Assignment 1 repository:** [InformationSecurity_Task-1_Group-9](https://github.com/embunabila/InformationSecurity_Task-1_Group-9)