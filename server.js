require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({ origin: true }));

const { PORT = 4000, MONGO_URI, JWT_SECRET } = process.env;

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connesso'))
  .catch(err => {
    console.error('❌ Errore connessione MongoDB:', err.message);
    process.exit(1);
  });

const { Schema, model } = mongoose;
const UserSchema = new Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true });
const User = model('User', UserSchema);

function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '1h' });
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token non valido o scaduto' });
  }
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email e password obbligatorie' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'Email già registrata' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, passwordHash });
    return res.status(201).json({ message: 'Registrazione ok', userId: user._id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Errore server' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email e password obbligatorie' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Credenziali non valide' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Credenziali non valide' });
    const token = signToken(user);
    return res.json({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Errore server' });
  }
});

app.get('/me', authRequired, (req, res) => {
  res.json({ userId: req.user.sub, email: req.user.email });
});

app.listen(PORT, () => console.log(`🚀 Server attivo su http://localhost:${PORT}`));

console.log("MONGO_URI:", process.env.MONGO_URI);
