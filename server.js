import express from "express";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// временное хранилище OTP (в памяти)
const otpStore = new Map();

// генерация 6-значного кода
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 📌 маршрут: отправка OTP
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ status: "error", message: "Email required" });
  }

  const otp = generateOTP();
  otpStore.set(email, { otp, expires: Date.now() + 60 * 1000 }); // 1 минута

  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.yokillc992@gmail.com,
        pass: process.env.qgerxurbrjjtiym
      },
    });

    await transporter.sendMail({
      from: `"OTP Service" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is: ${otp}. It will expire in 1 minute.`,
    });

    res.json({ status: "success", message: "OTP sent" });
  } catch (err) {
    console.error("Email error:", err);
    res.status(500).json({ status: "error", message: "Failed to send OTP" });
  }
});

// 📌 маршрут: проверка OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore.has(email)) {
    return res.status(400).json({ status: "error", message: "No OTP for this email" });
  }

  const { otp: storedOtp, expires } = otpStore.get(email);

  if (Date.now() > expires) {
    otpStore.delete(email);
    return res.status(400).json({ status: "error", message: "OTP expired" });
  }

  if (storedOtp !== otp) {
    return res.status(400).json({ status: "error", message: "Invalid OTP" });
  }

  otpStore.delete(email);
  res.json({ status: "success", message: "OTP verified" });
});

// Render даёт порт через process.env.PORT
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));