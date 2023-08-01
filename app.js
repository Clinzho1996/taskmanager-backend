require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const router = express.Router();

mongoose.connect(process.env.MONGODB_API);

const app = express();
const SECRET_KEY = process.env.SECRET_KEY_API;

app.listen(3000, () => console.log("App is running in http://localhost:3000"));

app.get("/api/register", function (req, res) {
  res.send("Api is live");
});
// middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));

// Utility function to generate a JWT token
const generateToken = (user) => {
  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1d" });
  return token;
};

// Utility function to verify a JWT token
const verifyToken = (token) => {
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch (err) {
    return null;
  }
};

// Middleware to check if a user is authenticated
const isAuthenticated = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) {
    return res.status(401).json({ error: "Unauthorized: Missing token" });
  }

  const decodedToken = verifyToken(token);
  if (!decodedToken) {
    return res.status(401).json({ error: "Unauthorized: Invalid token" });
  }

  req.userId = decodedToken.userId;
  next();
};

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

userSchema.pre("save", function (next) {
  const user = this;
  const saltRounds = 10;

  bcrypt.hash(user.password, saltRounds, (err, hash) => {
    if (err) return next(err);
    user.password = hash;
    next();
  });
});

const User = mongoose.model("User", userSchema);

// Routes for registration
app.post("/api/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: "Email already exists" });
    }

    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        return res.status(500).json({ error: "Failed to register user" });
      }

      const newUser = new User({ email, password: hash });
      await newUser.save(); // Use await to wait for the save operation to complete
      const token = generateToken(newUser);
      res.status(201).json({ message: "User registered successfully", token });
    });
  } catch (err) {
    return res.status(500).json({ error: "Failed to register user" });
  }
});

// routes for login
app.post("/api/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const passwordMatch = bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = generateToken(user);
    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    return res.status(500).json({ error: "Failed to log in" });
  }
});

// Reset Password Route
// Generate a reset token and store it in the database for the user
app.post("/api/forgot-password", async (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate a reset token
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Save the reset token and its expiration date in the database for the user
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // Token valid for 1 hour
    await user.save();

    // Send an email to the user with the reset token link
    const transporter = nodemailer.createTransport({
      // Set up your email transporter here (e.g., using SMTP or other providers)
      host: "smtp.elasticemail.com", // Replace with your SMTP host (e.g., smtp.gmail.com)
      port: 2525, // Replace with the SMTP port of your provider (e.g., 587 for Gmail)
      secure: false, // Set to true if using SSL/TLS (e.g., for Gmail, set to true and change the port to 465)
      auth: {
        user: "confidinho@yahoo.com", // Replace with your email address
        pass: process.env.SMTP_PASSWORD, // Replace with your email password
      },
    });

    const resetLink = `http://localhost:3000/api/reset-password/${resetToken}`;
    const mailOptions = {
      from: "confidinho@yahoo.com",
      to: email,
      subject: "Password Reset Request",
      text: `Click the following link to reset your password: ${resetLink}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log("Error sending email:", error);
        return res.status(500).json({ error: "Failed to send email" });
      }
      console.log("Email sent:", info.response);
      res.json({ message: "Password reset link sent to your email" });
    });
  } catch (err) {
    console.log("Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Reset the user's password
app.post("/api/reset-password/:token", async (req, res) => {
  const token = req.params.token;
  const newPassword = req.body.password;

  if (!newPassword) {
    return res.status(400).json({ error: "New password is required" });
  }

  try {
    // Find the user with the provided reset token and check if it's valid
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    // Update the user's password and clear the reset token fields
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.log("Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
