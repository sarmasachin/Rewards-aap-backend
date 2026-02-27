const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
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

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'));
    }
  }
});
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

    // Check if user is blocked or maintenance mode is on
    const isMaintenance = getConfig('app.maintenance_mode') === '1';
    if (isMaintenance) return res.status(503).json({ error: 'App is under maintenance. Please check back later.' });

    const u = db.prepare('SELECT is_blocked FROM users WHERE id = ?').get(req.user.userId);
    if (!u) return res.status(401).json({ error: 'User not found' });
    if (u.is_blocked === 1) return res.status(403).json({ error: 'Your account has been blocked' });

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

  const otp = String(crypto.randomInt(100000, 1000000));
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

  const tx = db.transaction(() => {
    let row = db.prepare('SELECT * FROM user_daily WHERE user_id = ? AND date = ?').get(req.user.userId, today);
    if (!row) db.prepare('INSERT INTO user_daily (user_id, date, opens) VALUES (?, ?, 1)').run(req.user.userId, today);
    else db.prepare('UPDATE user_daily SET opens = opens + 1 WHERE user_id = ? AND date = ?').run(req.user.userId, today);
    const openCount = (row ? row.opens : 0) + 1;
    const dailyBonus = openCount === 1 ? 5 : 0;
    if (dailyBonus > 0) db.prepare('UPDATE users SET diamonds = diamonds + ? WHERE id = ?').run(dailyBonus, req.user.userId);
    const u = db.prepare('SELECT diamonds FROM users WHERE id = ?').get(req.user.userId);
    return { openCountToday: openCount, dailyLoginBonus: dailyBonus, diamonds: u.diamonds };
  });

  try {
    const result = tx();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/home/stats', authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
  const d = db.prepare('SELECT * FROM user_daily WHERE user_id = ? AND date = ?').get(req.user.userId, today) || { ads_watched: 0, scratch_used: 0 };
  const adsWatched = d.ads_watched || 0;

  const dailyLimit = parseInt(getConfig('task.daily_limit') || '4', 10);
  const scratchUnlocked = adsWatched >= dailyLimit || (u.diamonds || 0) >= 50;

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
  const dailyLimit = parseInt(getConfig('task.daily_limit') || '4', 10);

  res.json({
    scratchUnlocked: adsWatched >= dailyLimit || (u.diamonds || 0) >= 50,
    scratchUsed: !!d.scratch_used,
    result: null,
    diamonds: u.diamonds || 0, weeklyUsed: 0, weeklyCap: 500,
    extraScratchBought: false, extraScratchDone: false, premiumScratchBought: false, premiumScratchDone: false
  });
});

app.post('/api/scratch/do', authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const rewardDiamonds = parseInt(getConfig('task.reward_diamonds') || '10', 10);

  const tx = db.transaction(() => {
    db.prepare('UPDATE user_daily SET scratch_used = 1 WHERE user_id = ? AND date = ?').run(req.user.userId, today);
    const rewards = [
      { id: '1', type: 'diamonds', label: `${rewardDiamonds} 💎`, value: rewardDiamonds, code: null },
      { id: '2', type: 'xp', label: '50 XP', value: 50, code: null },
      { id: '3', type: 'code', label: 'Reward Code', value: 0, code: 'FF2024' }
    ];
    const reward = rewards[Math.floor(Math.random() * rewards.length)];
    db.prepare('UPDATE users SET diamonds = diamonds + ?, xp = xp + ? WHERE id = ?').run(reward.type === 'diamonds' ? reward.value : 0, reward.type === 'xp' ? reward.value : 0, req.user.userId);
    db.prepare('INSERT INTO reward_items (user_id, type, label, value, code) VALUES (?, ?, ?, ?, ?)').run(req.user.userId, reward.type, reward.label, reward.value, reward.code);
    const u = db.prepare('SELECT diamonds, xp FROM users WHERE id = ?').get(req.user.userId);
    return { reward, xp: u.xp, weeklyUsed: 0, weeklyCap: 500 };
  });

  try {
    const result = tx();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Scratch failed due to an internal error.' });
  }
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
  const tx = db.transaction(() => {
    const prizes = [{ type: 'diamonds', label: '5 💎', value: 5 }, { type: 'xp', label: '20 XP', value: 20 }];
    const prize = prizes[Math.floor(Math.random() * prizes.length)];
    db.prepare('UPDATE users SET diamonds = diamonds + ?, xp = xp + ? WHERE id = ?').run(prize.type === 'diamonds' ? prize.value : 0, prize.type === 'xp' ? prize.value : 0, req.user.userId);
    const u = db.prepare('SELECT diamonds, xp FROM users WHERE id = ?').get(req.user.userId);
    return { success: true, prize: { id: '1', ...prize }, diamonds: u.diamonds, xp: u.xp };
  });

  try {
    const result = tx();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Spin failed due to an internal error.' });
  }
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

// --- NEW ADMIN APIs ---

// User Management
app.get('/admin/api/users', adminAuth, (req, res) => {
  const users = db.prepare('SELECT id, email, phone, ref_code, diamonds, xp, level, referral_count, is_blocked, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.put('/admin/api/users/:id', adminAuth, (req, res) => {
  const { diamonds, xp, is_blocked } = req.body || {};
  const userId = req.params.id;
  db.prepare('UPDATE users SET diamonds=?, xp=?, is_blocked=? WHERE id=?').run(
    diamonds !== undefined ? Number(diamonds) : 0,
    xp !== undefined ? Number(xp) : 0,
    is_blocked ? 1 : 0,
    userId
  );
  res.json({ ok: true });
});

// Reward Requests
app.get('/admin/api/reward-requests', adminAuth, (req, res) => {
  const requests = db.prepare(`
    SELECT r.id, r.user_id, r.status, r.requested_at, r.processed_at, c.title, c.cost_diamonds, c.cost_xp, u.email, u.phone
    FROM reward_requests r 
    JOIN coupons c ON r.coupon_id = c.id
    LEFT JOIN users u ON r.user_id = u.id
    ORDER BY r.requested_at DESC
  `).all();
  res.json(requests);
});

app.put('/admin/api/reward-requests/:id', adminAuth, (req, res) => {
  const { status } = req.body || {}; // APPROVED or REJECTED
  const reqId = parseInt(req.params.id, 10);
  const now = new Date().toISOString();

  if (status !== 'APPROVED' && status !== 'REJECTED') {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const tx = db.transaction(() => {
    const request = db.prepare('SELECT * FROM reward_requests WHERE id = ?').get(reqId);
    if (!request || request.status !== 'PENDING') return { error: 'Request not found or already processed' };

    db.prepare('UPDATE reward_requests SET status = ?, processed_at = ? WHERE id = ?').run(status, now, reqId);

    // If rejected, refund points
    if (status === 'REJECTED') {
      const coupon = db.prepare('SELECT cost_diamonds, cost_xp FROM coupons WHERE id = ?').get(request.coupon_id);
      if (coupon) {
        db.prepare('UPDATE users SET diamonds = diamonds + ?, xp = xp + ? WHERE id = ?').run(coupon.cost_diamonds, coupon.cost_xp, request.user_id);
      }
    }
    return { ok: true };
  });

  try {
    const result = tx();
    if (result.error) return res.status(400).json(result);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Coupons
app.get('/admin/api/coupons', adminAuth, (req, res) => {
  const coupons = db.prepare('SELECT * FROM coupons ORDER BY id').all();
  res.json(coupons);
});

app.post('/admin/api/coupons', adminAuth, (req, res) => {
  const { title, description, cost_diamonds, cost_xp, is_active } = req.body || {};
  db.prepare('INSERT INTO coupons (title, description, cost_diamonds, cost_xp, is_active) VALUES (?, ?, ?, ?, ?)')
    .run(title || '', description || '', Number(cost_diamonds) || 0, Number(cost_xp) || 0, is_active ? 1 : 0);
  res.json({ ok: true });
});

app.put('/admin/api/coupons/:id', adminAuth, (req, res) => {
  const { title, description, cost_diamonds, cost_xp, is_active } = req.body || {};
  db.prepare('UPDATE coupons SET title=?, description=?, cost_diamonds=?, cost_xp=?, is_active=? WHERE id=?')
    .run(title || '', description || '', Number(cost_diamonds) || 0, Number(cost_xp) || 0, is_active ? 1 : 0, parseInt(req.params.id, 10));
  res.json({ ok: true });
});

app.delete('/admin/api/coupons/:id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM coupons WHERE id = ?').run(parseInt(req.params.id, 10));
  res.json({ ok: true });
});

// Referrals
app.get('/admin/api/referrals', adminAuth, (req, res) => {
  const referrals = db.prepare(`
    SELECT id, email, phone, ref_code, referred_by, referral_count 
    FROM users 
    WHERE referred_by IS NOT NULL OR referral_count > 0
    ORDER BY referral_count DESC
  `).all();
  res.json(referrals);
});

// Reset Leaderboard
app.post('/admin/api/leaderboard/reset', adminAuth, (req, res) => {
  db.prepare('UPDATE users SET xp = 0').run();
  res.json({ ok: true });
});

// Fraud Alerts
app.get('/admin/api/fraud-alerts', adminAuth, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const suspiciousUsers = db.prepare(`
    SELECT u.id, u.email, u.phone, u.diamonds, d.ads_watched, d.scratch_used 
    FROM users u
    JOIN user_daily d ON u.id = d.user_id
    WHERE d.date = ? AND (d.ads_watched > 50 OR d.scratch_used > 50 OR u.diamonds > 10000)
  `).all(today);
  res.json(suspiciousUsers);
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
