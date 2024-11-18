const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const path = require('path');

// Initialize dotenv for environment variables
dotenv.config();

// Initialize express app
const app = express();

// Middleware for parsing JSON and form data
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.log('DB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  emailVerified: { type: Boolean, default: false },
  role: { type: String, enum: ['ops', 'client'], required: true },
  verificationToken: { type: String }
});

// File Schema
const fileSchema = new mongoose.Schema({
  fileName: { type: String, required: true },
  filePath: { type: String, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  fileType: { type: String, required: true },
  assignmentId: { type: String, unique: true, required: true },
  uploadDate: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);

// JWT Secret from .env
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// File upload handling with multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage: storage });

// User registration route
app.post('/signup', async (req, res) => {
  const { username, email, password, role } = req.body;
  try {
    const userExist = await User.findOne({ email });
    if (userExist) return res.status(400).json({ message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, role });

    // Generate verification token
    const token = crypto.randomBytes(20).toString('hex');
    newUser.verificationToken = token;

    await newUser.save();

    // Send email verification
    const verificationLink = `${process.env.BASE_URL}/email-verify/${token}`;
    transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Email Verification',
      text: `Please verify your email by clicking the link: ${verificationLink}`,
    });

    res.status(200).json({ message: 'Signup successful! Please check your email to verify.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// User login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Incorrect password' });

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Email verification route
app.get('/email-verify/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const user = await User.findOne({ verificationToken: token });
    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

    user.emailVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.status(200).json({ message: 'Email successfully verified' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// File upload route (Ops user only)
app.post('/upload', upload.single('file'), async (req, res) => {
  const { role, userId } = req.body;  // Assuming the JWT is decoded and role is available in body

  if (role !== 'ops') {
    return res.status(403).json({ message: 'Access Denied. Only Ops can upload files.' });
  }

  const file = req.file;
  const fileType = file.mimetype.split('/')[1];
  if (!['pptx', 'docx', 'xlsx'].includes(fileType)) {
    return res.status(400).json({ message: 'Only pptx, docx, and xlsx files are allowed.' });
  }

  try {
    const assignmentId = crypto.randomBytes(16).toString('hex');
    const newFile = new File({
      fileName: file.originalname,
      filePath: file.path,
      uploadedBy: userId,  // Assuming userId comes from JWT
      fileType,
      assignmentId,
    });

    await newFile.save();
    res.status(200).json({ message: 'File uploaded successfully', assignmentId });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Secure file download route (Client user only)
app.get('/download/:assignmentId', async (req, res) => {
  const { assignmentId } = req.params;
  const file = await File.findOne({ assignmentId });

  if (!file) return res.status(404).json({ message: 'File not found' });

  // Check if the user is a client and has permission
  const { role } = req.body;  // Assuming role is available from the JWT in the request body
  if (role !== 'client') {
    return res.status(403).json({ message: 'Access Denied. Only clients can download files.' });
  }

  // Generate encrypted download link
  const encryptedUrl = crypto.createCipher('aes-256-cbc', process.env.JWT_SECRET).update(file.filePath, 'utf8', 'hex');

  res.status(200).json({ downloadLink: encryptedUrl });
});

// Starting the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
