OTP server (Node.js + Express)
Endpoints:
POST /send-otp   { "email": "user@mail.com" }
POST /verify-otp { "email": "user@mail.com", "otp": "123456" }

Before running: create .env with EMAIL_USER and EMAIL_PASS (Gmail App Password).