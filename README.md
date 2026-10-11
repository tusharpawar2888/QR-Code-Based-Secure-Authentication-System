# Secure QR-Code Based Authentication System

A final-year B.Tech Information Technology project implementing cryptographically protected QR-based event/attendance authentication.

## Security concepts covered

- SHA-256 / HMAC-SHA256
- Message Authentication Code (MAC)
- Integrity and authenticity
- Timestamp-based expiry
- Random nonce
- Replay attack prevention
- QR tampering detection
- Fake QR detection
- One-time QR sessions
- Role-based authentication
- Password hashing
- HTTPS-ready architecture
- Security logs

## Technology

- Python
- Flask
- SQLite
- HMAC-SHA256
- QR Code
- HTML/CSS/JavaScript
- html5-qrcode for camera scanning

## Run on Windows

Open terminal in this folder:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

http://127.0.0.1:5000

## Demo accounts

### Admin
Email:
admin@college.local

Password:
Admin@123

### Student
Email:
tushar@college.local

Password:
Student@123

Other demo students use the same password:
- rahul@college.local
- amit@college.local

## Important production settings

Before deployment, set:

```powershell
$env:FLASK_SECRET_KEY="a-long-random-secret"
$env:QR_HMAC_SECRET="another-long-random-secret"
```

Never commit real secrets to GitHub.

## How to demonstrate the project

1. Login as admin.
2. Create an event.
3. Generate a secure QR.
4. Login as student on another browser/device.
5. Scan the QR.
6. Attendance is recorded.
7. Try scanning the same QR again — replay is blocked.
8. Try changing a QR payload — HMAC verification fails.
9. Wait for expiry and scan an old QR — it is rejected.
10. Open the admin dashboard to see attendance and security logs.

## Project flow

Admin -> Event -> Timestamp + Nonce -> HMAC-SHA256 -> QR

Student -> Scan QR -> Server -> HMAC check -> Timestamp check -> Nonce check -> Attendance

## Note about camera scanning

Camera access normally requires localhost or HTTPS. `http://127.0.0.1:5000` works for local development in modern browsers. For deployment, use HTTPS.
