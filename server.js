// server.js — Backend untuk PortofolioVerse
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET belum diisi di file .env — server berhenti demi keamanan.');
  console.error('   Isi .env dulu (lihat .env.example), lalu jalankan ulang.');
  process.exit(1);
}

// ============================================================
//  EMAIL — buat kirim kode verifikasi & reset password
// ============================================================
let transporter = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

async function sendEmail(to, subject, text) {
  if (!transporter) {
    // Belum dikonfigurasi — biar development tetap jalan, kode ditulis ke log server.
    // WAJIB diisi (lihat .env.example) sebelum aplikasi dipakai orang lain.
    console.warn(`⚠️  EMAIL_USER/EMAIL_PASS belum diisi di .env. Kode untuk ${to}: ${text}`);
    return;
  }
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to,
      subject,
      text,
    });
  } catch (err) {
    console.error('❌ Gagal mengirim email:', err.message);
  }
}

// ============================================================
//  MIDDLEWARE
// ============================================================
// CORS — default cuma izinkan localhost (dev). Set FRONTEND_URL di .env
// (boleh lebih dari satu, pisahkan koma) begitu frontend sudah di-deploy.
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5000,http://127.0.0.1:5000')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Origin tidak diizinkan oleh CORS.'));
  },
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Menyajikan frontend (public/index.html + public/api.js) di domain yang sama.
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
//  MONGODB CONNECTION
// ============================================================
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/portofolioverse')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ============================================================
//  SCHEMAS
// ============================================================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  verified: { type: Boolean, default: false },
  verificationCode: { type: String },
  title: { type: String, default: '' },
  location: { type: String, default: '' },
  bio: { type: String, default: '' },
  skills: [String],
  avatar: { type: String, default: null },
  cover: { type: String, default: null },
  organizations: [
    {
      id: String,
      name: String,
      role: String,
      startYear: String,
      endYear: String,
      description: String,
    },
  ],
  projects: [
    {
      id: String,
      title: String,
      description: String,
      images: [String],
      videos: [String],
      links: [String],
    },
  ],
  gallery: [
    {
      id: String,
      dataUrl: String,
      name: String,
      timestamp: Number,
    },
  ],
  activities: [
    {
      id: String,
      text: String,
      timestamp: Number,
    },
  ],
  following: [String],
  followers: [String],
  posts: [
    {
      id: String,
      content: String,
      media: [String],
      links: [String],
      timestamp: Number,
      likes: [String],
      comments: [
        {
          id: String,
          userId: String,
          text: String,
          timestamp: Number,
        },
      ],
      shares: { type: Number, default: 0 },
    },
  ],
  notifications: [
    {
      id: String,
      text: String,
      type: String,
      timestamp: Number,
      read: { type: Boolean, default: false },
    },
  ],
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  fromUserId: String,
  toUserId: String,
  text: String,
  timestamp: Number,
  read: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// ============================================================
//  MULTER — Upload file
// ============================================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  },
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

// ============================================================
//  AUTH MIDDLEWARE
// ============================================================
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Helper: buang field sensitif sebelum dikirim ke client
function toSafeUser(userDoc) {
  const safe = userDoc.toObject();
  delete safe.password;
  delete safe.verificationCode;
  return safe;
}

// ============================================================
//  AUTH ROUTES
// ============================================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: 'Semua field wajib diisi.' });
    }
    const existing = await User.findOne({ $or: [{ email }, { phone }] });
    if (existing) {
      return res.status(400).json({ error: 'Email atau telepon sudah terdaftar.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const user = new User({
      name,
      email,
      phone,
      password: hashed,
      verificationCode: code,
      verified: false,
    });
    await user.save();
    await sendEmail(email, 'Kode Verifikasi PortofolioVerse', `Kode verifikasi akun Anda: ${code}\n\nKode ini untuk pendaftaran akun PortofolioVerse. Jangan bagikan ke siapa pun.`);
    res.json({ message: 'Registrasi berhasil! Cek email Anda untuk kode verifikasi.', email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User tidak ditemukan.' });
    if (user.verified) return res.json({ message: 'Akun sudah terverifikasi.' });
    if (user.verificationCode === code) {
      user.verified = true;
      user.verificationCode = null;
      await user.save();
      res.json({ message: 'Verifikasi berhasil!' });
    } else {
      res.status(400).json({ error: 'Kode verifikasi salah.' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/resend-code', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'Email tidak ditemukan.' });
    if (user.verified) return res.json({ message: 'Akun sudah terverifikasi. Silakan login.' });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    user.verificationCode = code;
    await user.save();
    await sendEmail(email, 'Kode Verifikasi PortofolioVerse', `Kode verifikasi akun Anda: ${code}\n\nKode ini untuk pendaftaran akun PortofolioVerse. Jangan bagikan ke siapa pun.`);
    res.json({ message: 'Kode verifikasi baru telah dikirim.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'Email tidak ditemukan.' });
    if (!user.verified) {
      return res.status(400).json({ error: 'Akun belum diverifikasi.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Password salah.' });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'Email tidak ditemukan.' });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    user.verificationCode = code;
    await user.save();
    await sendEmail(email, 'Kode Reset Password PortofolioVerse', `Kode reset password Anda: ${code}\n\nKalau Anda tidak meminta ini, abaikan email ini.`);
    res.json({ message: 'Kode reset telah dikirim ke email Anda.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/reset', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'Email tidak ditemukan.' });
    if (user.verificationCode !== code) {
      return res.status(400).json({ error: 'Kode reset salah.' });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    user.verificationCode = null;
    await user.save();
    res.json({ message: 'Password berhasil direset.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  USER ROUTES
// ============================================================
app.get('/api/users/me', auth, async (req, res) => {
  res.json(toSafeUser(req.user));
});

app.get('/api/users', auth, async (req, res) => {
  const users = await User.find({ _id: { $ne: req.user._id } }).select('-password -verificationCode');
  res.json(users);
});

app.get('/api/users/:id', auth, async (req, res) => {
  const user = await User.findById(req.params.id).select('-password -verificationCode');
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan.' });
  res.json(user);
});

app.put('/api/users/me', auth, async (req, res) => {
  try {
    const updates = { ...req.body };
    // Field yang nggak boleh diubah lewat endpoint ini — sengaja diblokir di server,
    // bukan cuma diandalkan dari frontend, supaya aman walau ada yang panggil API langsung.
    ['_id', '__v', 'password', 'email', 'verified', 'verificationCode', 'following', 'followers', 'posts', 'createdAt', 'updatedAt']
      .forEach(f => delete updates[f]);
    Object.assign(req.user, updates);
    await req.user.save();
    res.json(toSafeUser(req.user));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Follow / Unfollow
app.post('/api/users/follow/:id', auth, async (req, res) => {
  try {
    const target = await User.findById(req.params.id);
    if (!target) return res.status(404).json({ error: 'User tidak ditemukan.' });
    if (req.user._id.toString() === target._id.toString()) {
      return res.status(400).json({ error: 'Tidak bisa mengikuti diri sendiri.' });
    }
    const idx = req.user.following.indexOf(target._id.toString());
    if (idx === -1) {
      req.user.following.push(target._id.toString());
      target.followers.push(req.user._id.toString());
      target.notifications.push({
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        text: `${req.user.name} mulai mengikuti Anda.`,
        type: 'follow',
        timestamp: Date.now(),
        read: false,
      });
    } else {
      req.user.following.splice(idx, 1);
      const idx2 = target.followers.indexOf(req.user._id.toString());
      if (idx2 !== -1) target.followers.splice(idx2, 1);
    }
    await req.user.save();
    await target.save();
    res.json({ following: req.user.following });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  POST ROUTES
// ============================================================
app.post('/api/posts', auth, async (req, res) => {
  try {
    const { content, media, links } = req.body;
    const post = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      content: content || '📎 Media',
      media: media || [],
      links: links || [],
      timestamp: Date.now(),
      likes: [],
      comments: [],
      shares: 0,
    };
    req.user.posts.push(post);
    for (const fId of req.user.followers) {
      const follower = await User.findById(fId);
      if (follower) {
        follower.notifications.push({
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
          text: `${req.user.name} membuat postingan baru: "${(content || '').slice(0, 50)}..."`,
          type: 'post',
          timestamp: Date.now(),
          read: false,
        });
        await follower.save();
      }
    }
    await req.user.save();
    res.json({ ...post, userId: req.user._id.toString(), userName: req.user.name, userAvatar: req.user.avatar });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/posts/feed', auth, async (req, res) => {
  try {
    const userIds = [req.user._id.toString(), ...req.user.following];
    const users = await User.find({ _id: { $in: userIds } }).select('posts name avatar');
    let allPosts = [];
    users.forEach(u => {
      u.posts.forEach(p => {
        allPosts.push({
          ...p.toObject(),
          userId: u._id,
          userName: u.name,
          userAvatar: u.avatar,
        });
      });
    });
    allPosts.sort((a, b) => b.timestamp - a.timestamp);
    res.json(allPosts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/posts/global', auth, async (req, res) => {
  try {
    const users = await User.find().select('posts name avatar');
    let allPosts = [];
    users.forEach(u => {
      u.posts.forEach(p => {
        allPosts.push({
          ...p.toObject(),
          userId: u._id,
          userName: u.name,
          userAvatar: u.avatar,
        });
      });
    });
    allPosts.sort((a, b) => b.timestamp - a.timestamp);
    res.json(allPosts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:postId/like', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    let foundUser = null;
    let foundPost = null;
    const allUsers = await User.find();
    for (const u of allUsers) {
      const p = u.posts.find(pp => pp.id === postId);
      if (p) {
        foundUser = u;
        foundPost = p;
        break;
      }
    }
    if (!foundPost) return res.status(404).json({ error: 'Post tidak ditemukan.' });
    const idx = foundPost.likes.indexOf(req.user._id.toString());
    if (idx === -1) {
      foundPost.likes.push(req.user._id.toString());
      if (foundUser._id.toString() !== req.user._id.toString()) {
        foundUser.notifications.push({
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
          text: `${req.user.name} menyukai postingan Anda.`,
          type: 'like',
          timestamp: Date.now(),
          read: false,
        });
      }
    } else {
      foundPost.likes.splice(idx, 1);
    }
    await foundUser.save();
    res.json({ likes: foundPost.likes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:postId/comment', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Komentar kosong.' });
    let foundUser = null;
    let foundPost = null;
    const allUsers = await User.find();
    for (const u of allUsers) {
      const p = u.posts.find(pp => pp.id === postId);
      if (p) {
        foundUser = u;
        foundPost = p;
        break;
      }
    }
    if (!foundPost) return res.status(404).json({ error: 'Post tidak ditemukan.' });
    const comment = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      userId: req.user._id.toString(),
      text,
      timestamp: Date.now(),
    };
    foundPost.comments.push(comment);
    if (foundUser._id.toString() !== req.user._id.toString()) {
      foundUser.notifications.push({
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        text: `${req.user.name} mengomentari postingan Anda.`,
        type: 'comment',
        timestamp: Date.now(),
        read: false,
      });
    }
    await foundUser.save();
    res.json({ comments: foundPost.comments });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:postId/share', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    let foundUser = null;
    let foundPost = null;
    const allUsers = await User.find();
    for (const u of allUsers) {
      const p = u.posts.find(pp => pp.id === postId);
      if (p) {
        foundUser = u;
        foundPost = p;
        break;
      }
    }
    if (!foundPost) return res.status(404).json({ error: 'Post tidak ditemukan.' });
    foundPost.shares = (foundPost.shares || 0) + 1;
    if (foundUser._id.toString() !== req.user._id.toString()) {
      foundUser.notifications.push({
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        text: `${req.user.name} membagikan postingan Anda.`,
        type: 'share',
        timestamp: Date.now(),
        read: false,
      });
    }
    await foundUser.save();
    res.json({ shares: foundPost.shares });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/posts/:postId', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    const idx = req.user.posts.findIndex(p => p.id === postId);
    if (idx === -1) return res.status(404).json({ error: 'Post tidak ditemukan.' });
    req.user.posts.splice(idx, 1);
    await req.user.save();
    res.json({ message: 'Postingan dihapus.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  MESSAGES
// ============================================================
app.post('/api/messages', auth, async (req, res) => {
  try {
    const { toUserId, text } = req.body;
    if (!text) return res.status(400).json({ error: 'Pesan kosong.' });
    const msg = new Message({
      fromUserId: req.user._id.toString(),
      toUserId,
      text,
      timestamp: Date.now(),
      read: false,
    });
    await msg.save();
    const target = await User.findById(toUserId);
    if (target) {
      target.notifications.push({
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        text: `Pesan baru dari ${req.user.name}: "${text.slice(0, 40)}${text.length > 40 ? '...' : ''}"`,
        type: 'message',
        timestamp: Date.now(),
        read: false,
      });
      await target.save();
    }
    res.json(msg);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/messages/:userId', auth, async (req, res) => {
  try {
    const { userId } = req.params;
    const msgs = await Message.find({
      $or: [
        { fromUserId: req.user._id.toString(), toUserId: userId },
        { fromUserId: userId, toUserId: req.user._id.toString() },
      ],
    }).sort({ timestamp: 1 });
    await Message.updateMany(
      { fromUserId: userId, toUserId: req.user._id.toString(), read: false },
      { read: true }
    );
    res.json(msgs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/messages/threads', auth, async (req, res) => {
  try {
    const msgs = await Message.find({
      $or: [
        { fromUserId: req.user._id.toString() },
        { toUserId: req.user._id.toString() },
      ],
    }).sort({ timestamp: -1 });
    const threads = [];
    const seen = new Set();
    msgs.forEach(m => {
      const other = m.fromUserId === req.user._id.toString() ? m.toUserId : m.fromUserId;
      if (!seen.has(other)) {
        seen.add(other);
        threads.push({ userId: other, lastMessage: m });
      }
    });
    res.json(threads);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  UPLOAD FILE
// ============================================================
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file.' });
  const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ url });
});

// ============================================================
//  START SERVER
// ============================================================
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  if (!transporter) {
    console.warn('⚠️  Email belum dikonfigurasi — kode verifikasi/reset akan tampil di log ini saja (lihat .env.example).');
  }
});
