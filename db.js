const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'data.db'));

// Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT,
    phone TEXT,
    ref_code TEXT UNIQUE,
    diamonds INTEGER DEFAULT 0,
    xp INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    streak INTEGER DEFAULT 0,
    calendar_streak INTEGER DEFAULT 0,
    referral_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_daily (
    user_id TEXT,
    date TEXT,
    opens INTEGER DEFAULT 0,
    ads_watched INTEGER DEFAULT 0,
    scratch_used INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, date)
  );

  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  CREATE TABLE IF NOT EXISTS feature_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sort_order INTEGER DEFAULT 0,
    title TEXT,
    description TEXT,
    image_url TEXT,
    gradient_id INTEGER DEFAULT 1,
    show_ad INTEGER DEFAULT 0,
    link_type TEXT,
    link_value TEXT
  );

  CREATE TABLE IF NOT EXISTS reward_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    type TEXT,
    label TEXT,
    value INTEGER DEFAULT 0,
    code TEXT,
    claimed_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS email_otps (
    email TEXT,
    otp TEXT,
    expires_at TEXT,
    used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Seed default config
const defaults = {
  'theme.primary': '#D4A853',
  'theme.primaryDark': '#B8923F',
  'theme.accent': '#D4A853',
  'theme.background': '#FFF5F5F5',
  'theme.surface': '#FFFFFFFF',
  'theme.success': '#FF34C759',
  'logo.url': '',
  'strings.app_name': 'Scratch Rewards',
  'strings.phone': 'Phone number',
  'strings.send_otp': 'Send OTP',
  'strings.login': 'Login',
  'strings.home': 'Home',
  'strings.wallet': 'Wallet',
  'strings.profile': 'Profile',
  'strings.leaderboard': 'Leaderboard',
  'strings.store': 'Store',
  'admin.password': 'admin123'
};

const st = db.prepare('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)');
for (const [k, v] of Object.entries(defaults)) st.run(k, v);

// Seed default feature cards (home)
const cardCount = db.prepare('SELECT COUNT(*) as c FROM feature_cards').get();
if (cardCount.c === 0) {
  const ins = db.prepare('INSERT INTO feature_cards (sort_order, title, description, gradient_id, show_ad, link_type) VALUES (?, ?, ?, ?, ?, ?)');
  ins.run(0, 'FF Skin Tool', 'Unlock customize, characters, redemptions!', 1, 0, 'scratch');
  ins.run(1, 'Get rank emotes skin', 'You get rank in ff game avatar skin', 2, 1, 'rewards');
  ins.run(2, 'Emotes Skin', 'You get different avatars in ff emotes skin', 3, 0, null);
  ins.run(3, 'Play Free Game', 'You get free diamond in ff game skin', 4, 1, null);
}

module.exports = db;
