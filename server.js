const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'scratch-rewards-secret-change-in-production';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || null;

const allowedOriginsEnv = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);
if (allowedOriginsEnv.length === 0) {
  app.use(cors());
} else {
  app.use(cors({
    origin(origin, cb) {
      if (!origin || allowedOriginsEnv.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS'), false);
    }
  }));
}

app.use(express.json());
app.use('/api/uploads', express.static(path.join(__dirname, 'uploads')));

const upload = multer({ dest: 'uploads/', limits: { fileSize: 2 * 1024 * 1024 } });
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// ----- Helpers -----
function getConfig(key) {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get(key);
  return row ? row.value : null;
}
function setConfig(key, value) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(key, String(value));
}
function allConfig(prefix) {
  const rows = db.prepare("SELECT key, value FROM config WHERE key LIKE ?").all(prefix ? prefix + '%' : '%');
  const out = {};
  rows.forEach(r => { out[r.key] = r.value; });
  return out;
}
function getAdminPassword() {
  return process.env.ADMIN_PASSWORD || getConfig('admin.password');
}
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
function makeUserRow(u) {
  return {
    id: u.id,
    phone: u.phone || null,
    refCode: u.ref_code || null,
    diamonds: u.diamonds || 0,
    xp: u.xp || 0,
    level: u.level || 1,
    streak: u.streak || 0,
    calendarStreak: u.calendar_streak || 0,
    referralCount: u.referral_count || 0,
    badges: []
  };
}

// Google client and mailer
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
let mailTransport = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
    secure: !!process.env.SMTP_SECURE,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

// ----- App API -----

// Config for app (colors, logo, strings, feature cards) - no auth
app.get('/api/config', (req, res) => {
  const theme = {};
  const strings = {};
  const raw = allConfig();
  Object.entries(raw).forEach(([k, v]) => {
    if (k.startsWith('theme.')) theme[k.replace('theme.', '')] = v;
    if (k.startsWith('strings.')) strings[k.replace('strings.', '')] = v;
  });
  const cards = db.prepare('SELECT * FROM feature_cards ORDER BY sort_order').all();
  res.json({
    theme: { primary: theme.primary || '#D4A853', primaryDark: theme.primaryDark || '#B8923F', accent: theme.accent, background: theme.background, surface: theme.surface, success: theme.success },
    logoUrl: getConfig('logo.url') || '',
    strings,
    featureCards: cards.map(c => ({ id: c.id, title: c.title, description: c.description, imageUrl: c.image_url, gradientId: c.gradient_id, showAd: !!c.show_ad, linkType: c.link_type, linkValue: c.link_value }))
  });
});

// Auth - Google (verify idToken)
app.post('/api/auth/google', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!GOOGLE_CLIENT_ID || !googleClient) {
      return res.status(500).json({ error: 'Google login not configured (GOOGLE_CLIENT_ID missing)' });
    }
    if (!idToken) return res.status(400).json({ error: 'idToken required' });

    const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload) return res.status(401).json({ error: 'Invalid Google token' });

    const sub = payload.sub;
    const email = payload.email;
    const userId = 'g_' + sub;

    let u = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!u) {
      const refCode = 'REF' + Math.random().toString(36).slice(2, 8).toUpperCase();
      db.prepare('INSERT INTO users (id, email, ref_code) VALUES (?, ?, ?)').run(userId, email || null, refCode);
      u = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    }
    const token = jwt.sign({ userId: u.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: makeUserRow(u) });
  } catch (e) {
    console.error('Google auth failed', e.message);
    res.status(401).json({ error: 'Google login failed' });
  }
});

// Email OTP with DB + optional SMTP
app.post('/api/auth/send-email-otp', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO email_otps (email, otp, expires_at) VALUES (?, ?, ?)').run(email, otp, expiresAt);

  if (mailTransport) {
    try {
      await mailTransport.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: 'Your Scratch Rewards OTP',
        text: `Your login OTP is ${otp}. It will expire in 10 minutes.`
      });
    } catch (e) {
      console.error('OTP email send failed', e.message);
    }
  } else {
    console.log('LOGIN OTP for', email, '=>', otp);
  }
  res.status(200).send();
});

app.post('/api/auth/verify-email-otp', (req, res) => {
  const { email, otp } = req.body || {};
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
  const now = new Date().toISOString();
  const row = db.prepare('SELECT * FROM email_otps WHERE email = ? AND otp = ? AND used = 0 AND expires_at > ? ORDER BY created_at DESC').get(email, otp, now);
  if (!row) return res.status(401).json({ error: 'Invalid or expired OTP' });
  db.prepare('UPDATE email_otps SET used = 1 WHERE email = ? AND otp = ?').run(email, otp);

  const baseId = 'e_' + email.replace(/\\W/g, '');
  let u = db.prepare('SELECT * FROM users WHERE id = ?').get(baseId);
  if (!u) {
    const refCode = 'REF' + Math.random().toString(36).slice(2, 8).toUpperCase();
    db.prepare('INSERT INTO users (id, email, ref_code) VALUES (?, ?, ?)').run(baseId, email, refCode);
    u = db.prepare('SELECT * FROM users WHERE id = ?').get(baseId);
  }
  const token = jwt.sign({ userId: u.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: makeUserRow(u) });
});

app.post('/api/app/open', authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  let row = db.prepare('SELECT * FROM user_daily WHERE user_id = ? AND date = ?').get(req.user.userId, today);
  if (!row) db.prepare('INSERT INTO user_daily (user_id, date, opens) VALUES (?, ?, 1)').run(req.user.userId, today);
  else db.prepare('UPDATE user_daily SET opens = opens + 1 WHERE user_id = ? AND date = ?').run(req.user.userId, today);
  const openCount = (row ? row.opens : 0) + 1;
  const dailyBonus = openCount === 1 ? 5 : 0;
  if (dailyBonus > 0) db.prepare('UPDATE users SET diamonds = diamonds + ? WHERE id = ?').run(dailyBonus, req.user.userId);
  const u = db.prepare('SELECT diamonds FROM users WHERE id = ?').get(req.user.userId);
  res.json({ openCountToday: openCount, dailyLoginBonus: dailyBonus, diamonds: u.diamonds });
});

app.get('/api/home/stats', authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
  const d = db.prepare('SELECT * FROM user_daily WHERE user_id = ? AND date = ?').get(req.user.userId, today) || { ads_watched: 0, scratch_used: 0 };
  const adsWatched = d.ads_watched || 0;
  const scratchUnlocked = adsWatched >= 4 || (u.diamonds || 0) >= 50;
  res.json({
    openCountToday: 1, adsWatchedToday: adsWatched, scratchUnlocked, scratchUsed: !!d.scratch_used, scratchResult: null,
    diamonds: u.diamonds || 0, xp: u.xp || 0, level: u.level || 1, streak: u.streak || 0, calendarStreak: u.calendar_streak || 0,
    referralCount: u.referral_count || 0, refCode: u.ref_code, badges: [], weeklyUsed: 0, weeklyCap: 500, todayUsersWon: 0,
    shareUsedToday: false, canClaimComeback: false, wheelCanSpin: true,
    extraScratchBought: false, extraScratchDone: false, premiumScratchBought: false, premiumScratchDone: false
  });
});

app.post('/api/task/watch-ad', authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  let d = db.prepare('SELECT * FROM user_daily WHERE user_id = ? AND date = ?').get(req.user.userId, today);
  if (!d) db.prepare('INSERT INTO user_daily (user_id, date, ads_watched) VALUES (?, ?, 1)').run(req.user.userId, today);
  else db.prepare('UPDATE user_daily SET ads_watched = ads_watched + 1 WHERE user_id = ? AND date = ?').run(req.user.userId, today);
  res.json({});
});

app.get('/api/scratch/status', authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const d = db.prepare('SELECT * FROM user_daily WHERE user_id = ? AND date = ?').get(req.user.userId, today) || {};
  const u = db.prepare('SELECT diamonds FROM users WHERE id = ?').get(req.user.userId);
  const adsWatched = d.ads_watched || 0;
  res.json({
    scratchUnlocked: adsWatched >= 4 || (u.diamonds || 0) >= 50,
    scratchUsed: !!d.scratch_used,
    result: null,
    diamonds: u.diamonds || 0, weeklyUsed: 0, weeklyCap: 500,
    extraScratchBought: false, extraScratchDone: false, premiumScratchBought: false, premiumScratchDone: false
  });
});

app.post('/api/scratch/do', authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  db.prepare('UPDATE user_daily SET scratch_used = 1 WHERE user_id = ? AND date = ?').run(req.user.userId, today);
  const rewards = [{ id: '1', type: 'diamonds', label: '10 💎', value: 10, code: null }, { id: '2', type: 'xp', label: '50 XP', value: 50, code: null }, { id: '3', type: 'code', label: 'Reward Code', value: 0, code: 'FF2024' }];
  const reward = rewards[Math.floor(Math.random() * rewards.length)];
  db.prepare('UPDATE users SET diamonds = diamonds + ?, xp = xp + ? WHERE id = ?').run(reward.type === 'diamonds' ? reward.value : 0, reward.type === 'xp' ? reward.value : 0, req.user.userId);
  db.prepare('INSERT INTO reward_items (user_id, type, label, value, code) VALUES (?, ?, ?, ?, ?)').run(req.user.userId, reward.type, reward.label, reward.value, reward.code);
  const u = db.prepare('SELECT diamonds, xp FROM users WHERE id = ?').get(req.user.userId);
  res.json({ reward, xp: u.xp, weeklyUsed: 0, weeklyCap: 500 });
});

app.post('/api/scratch/unlock-with-diamonds', authMiddleware, (req, res) => {
  db.prepare('UPDATE users SET diamonds = diamonds - 50 WHERE id = ? AND diamonds >= 50').run(req.user.userId);
  res.json({});
});

app.post('/api/scratch/do-extra', authMiddleware, (req, res) => res.json({ reward: { label: 'Extra', value: 0 }, xp: 0 }));
app.post('/api/scratch/do-premium', authMiddleware, (req, res) => res.json({ reward: { label: 'Premium', value: 0 }, xp: 0 }));

app.get('/api/wheel/status', authMiddleware, (req, res) => {
  const u = db.prepare('SELECT diamonds FROM users WHERE id = ?').get(req.user.userId);
  res.json({ canSpin: true, usedToday: false, diamonds: u.diamonds || 0 });
});
app.post('/api/wheel/spin', authMiddleware, (req, res) => {
  const prizes = [{ type: 'diamonds', label: '5 💎', value: 5 }, { type: 'xp', label: '20 XP', value: 20 }];
  const prize = prizes[Math.floor(Math.random() * prizes.length)];
  db.prepare('UPDATE users SET diamonds = diamonds + ?, xp = xp + ? WHERE id = ?').run(prize.type === 'diamonds' ? prize.value : 0, prize.type === 'xp' ? prize.value : 0, req.user.userId);
  const u = db.prepare('SELECT diamonds, xp FROM users WHERE id = ?').get(req.user.userId);
  res.json({ success: true, prize: { id: '1', ...prize }, diamonds: u.diamonds, xp: u.xp });
});

app.post('/api/store/extra-scratch', authMiddleware, (req, res) => res.json({}));
app.post('/api/store/premium-scratch', authMiddleware, (req, res) => res.json({}));

app.get('/api/rewards/list', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT type, label, value, code, claimed_at as at FROM reward_items WHERE user_id = ? ORDER BY claimed_at DESC').all(req.user.userId);
  res.json({ rewards: rows.map(r => ({ type: r.type, label: r.label, value: r.value, code: r.code, at: r.at })) });
});

app.get('/api/leaderboard', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT id, ref_code, xp FROM users ORDER BY xp DESC LIMIT 20').all();
  res.json({ leaderboard: rows.map((r, i) => ({ userId: r.id, name: r.ref_code, xp: r.xp, rank: i + 1 })) });
});

app.get('/api/profile', authMiddleware, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
  res.json({ ...makeUserRow(u), weeklyUsed: 0, weeklyCap: 500, badgeDiamondRewards: null });
});

app.post('/api/share/claim', authMiddleware, (req, res) => res.json({}));
app.post('/api/comeback/claim', authMiddleware, (req, res) => res.json({}));
app.post('/api/calendar/claim', authMiddleware, (req, res) => res.json({}));

// Legacy (if app still calls)
app.post('/api/auth/send-otp', (req, res) => res.status(200).send());
app.post('/api/auth/verify', (req, res) => {
  const id = 'u_phone_' + Date.now();
  db.prepare('INSERT OR IGNORE INTO users (id, ref_code) VALUES (?, ?)').run(id, 'REF' + Math.random().toString(36).slice(2, 8).toUpperCase());
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.json({ token: jwt.sign({ userId: u.id }, JWT_SECRET, { expiresIn: '30d' }), user: makeUserRow(u) });
});

// ----- Admin API (simple auth: password in config/env) -----
function adminAuth(req, res, next) {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  const pwd = getAdminPassword();
  if (!pwd || auth !== pwd) return res.status(401).json({ error: 'Wrong admin password' });
  next();
}

app.get('/admin/api/config', adminAuth, (req, res) => {
  res.json(allConfig());
});

app.post('/admin/api/config', adminAuth, (req, res) => {
  const body = req.body || {};
  Object.entries(body).forEach(([k, v]) => setConfig(k, v));
  res.json({ ok: true });
});

app.post('/admin/api/logo', adminAuth, upload.single('logo'), (req, res) => {
  if (req.file) {
    const pathUrl = '/api/uploads/' + req.file.filename;
    const fullUrl = (req.protocol + '://' + req.get('host') + pathUrl).replace(/^undefined/, 'http://localhost:' + PORT);
    setConfig('logo.url', fullUrl);
    res.json({ ok: true, url: fullUrl });
  } else res.status(400).json({ error: 'No file' });
});

app.get('/admin/api/feature-cards', adminAuth, (req, res) => {
  const cards = db.prepare('SELECT * FROM feature_cards ORDER BY sort_order').all();
  res.json(cards);
});

app.post('/admin/api/feature-cards', adminAuth, (req, res) => {
  const { title, description, imageUrl, gradientId, showAd, linkType, linkValue, sortOrder } = req.body || {};
  db.prepare('INSERT INTO feature_cards (sort_order, title, description, image_url, gradient_id, show_ad, link_type, link_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sortOrder ?? 0, title ?? '', description ?? '', imageUrl ?? '', gradientId ?? 1, showAd ? 1 : 0, linkType ?? null, linkValue ?? null);
  res.json({ ok: true, id: db.prepare('SELECT last_insert_rowid() as id').get().id });
});

app.put('/admin/api/feature-cards/:id', adminAuth, (req, res) => {
  const { title, description, imageUrl, gradientId, showAd, linkType, linkValue, sortOrder } = req.body || {};
  const id = parseInt(req.params.id, 10);
  db.prepare('UPDATE feature_cards SET sort_order=?, title=?, description=?, image_url=?, gradient_id=?, show_ad=?, link_type=?, link_value=? WHERE id=?')
    .run(sortOrder ?? 0, title ?? '', description ?? '', imageUrl ?? '', gradientId ?? 1, showAd ? 1 : 0, linkType ?? null, linkValue ?? null, id);
  res.json({ ok: true });
});

app.delete('/admin/api/feature-cards/:id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM feature_cards WHERE id = ?').run(parseInt(req.params.id, 10));
  res.json({ ok: true });
});

// Serve admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'admin')));

app.listen(PORT, () => {
  console.log('Scratch Rewards Backend + Admin running at http://localhost:' + PORT);
  console.log('Admin panel: http://localhost:' + PORT + '/admin');
});
