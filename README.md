# Scratch Rewards – Backend + Admin

Backend **Node.js (Express)** + **SQLite** + **Admin panel** – app ke liye API aur aapke **full control** ke liye (colors, logo, text, feature cards).

---

## Install & Run

```bash
cd C:\Users\DELL\Desktop\ScratchRewardsBackend
npm install
npm start
```

- **API:** http://localhost:3001/api/
- **Admin panel:** http://localhost:3001/admin

---

## Admin Panel (Full Control)

1. Browser me open karo: **http://localhost:3001/admin**
2. **Password:** `admin123` (pehli baar; baad me config me change kar sakte ho)
3. Yahan se kar sakte ho:
   - **Theme / Colors** – Primary, Primary Dark, Accent, Background, Surface, Success (save = app config me save)
   - **Logo** – URL daalo ya file upload karo
   - **App Text (Strings)** – app_name, phone, login, home, wallet, etc. – sab text edit
   - **Feature Cards** – Home wale cards: Title, Description, Gradient (1–5), AD badge, Link (scratch / rewards) – Add, Edit, Delete

Sab changes **config** me save hote hain. App **GET /api/config** se yehi colors, logo, strings, feature cards leti hai (agar app me config API use kiya ho).

---

## App Ko Backend Se Connect

Android app me **ApiConfig.BASE_URL** ko apne server ka URL do:

- Emulator: `http://10.0.2.2:3001/api/`
- Real device (same WiFi): `http://<your-pc-ip>:3001/api/`
- Deploy: `https://your-domain.com/api/`

---

## API Endpoints (App ke liye)

- `GET /api/config` – theme, logo, strings, feature cards (no auth)
- `POST /api/auth/google`, `/api/auth/verify-email-otp` – login
- `POST /api/app/open`, `GET /api/home/stats` – home
- `POST /api/task/watch-ad`, `GET /api/scratch/status`, `POST /api/scratch/do` – scratch
- `GET /api/rewards/list`, `GET /api/profile`, `GET /api/leaderboard` – rewards, profile, leaderboard
- Wheel, store, share, comeback, calendar – sab implemented

---

## Admin Password Change

Abhi admin password **config** me key `admin.password` me hai (default `admin123`).  
Password change karne ke liye: admin panel me koi “Admin password” field nahi hai – abhi manually DB me ya baad me admin panel me “Settings” add karke `admin.password` update karna hoga.  
Direct DB: `data.db` open karo, `config` table me `admin.password` ki value change karo.
