const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const TOKEN_SECRET = process.env.TOKEN_SECRET || ADMIN_PASSWORD;

if (!MONGODB_URI || !ADMIN_PASSWORD) {
  console.error('MONGODB_URI and ADMIN_PASSWORD are required');
  process.exit(1);
}

// ---------- সাইটের API Key ----------
const SITES = [];
if (process.env.RSGALLERY_KEY) SITES.push({ key: process.env.RSGALLERY_KEY, name: 'rsgallery' });
if (process.env.RSMATRIX_KEY) SITES.push({ key: process.env.RSMATRIX_KEY, name: 'rsmatrix' });

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function siteAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ ok: false, error: 'API key দিন' });
  let found = null;
  for (const s of SITES) {
    if (safeEqual(key, s.key)) found = s;
  }
  if (!found) return res.status(401).json({ ok: false, error: 'ভুল API key' });
  req.site = found.name;
  next();
}

// ---------- অ্যাডমিন টোকেন ----------
function signToken() {
  const exp = String(Date.now() + 7 * 24 * 3600 * 1000);
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(exp).digest('hex');
  return exp + '.' + sig;
}

function verifyToken(t) {
  if (!t) return false;
  const parts = String(t).split('.');
  if (parts.length !== 2) return false;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(parts[0]).digest('hex');
  if (!safeEqual(parts[1], expected)) return false;
  return Number(parts[0]) > Date.now();
}

function adminAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!verifyToken(token)) return res.status(401).json({ ok: false, error: 'লগইন করুন' });
  next();
}

// লগইনে ভুল পাসওয়ার্ড দিলে ব্লক
const attempts = new Map();
function loginBlocked(ip) {
  const a = attempts.get(ip);
  return a && a.until && a.until > Date.now();
}
function loginFail(ip) {
  const a = attempts.get(ip) || { count: 0, until: 0 };
  a.count += 1;
  if (a.count >= 5) {
    a.until = Date.now() + 15 * 60 * 1000;
    a.count = 0;
  }
  attempts.set(ip, a);
}

// ---------- ডাটাবেস মডেল ----------
const txSchema = new mongoose.Schema(
  {
    type: { type: String, enum: ['deposit', 'payout'], required: true },
    site: { type: String, default: 'manual' },
    amount: { type: Number, required: true, min: 1 },
    method: { type: String, default: 'bkash' },
    number: String,
    trxId: { type: String, uppercase: true, trim: true },
    orderRef: String,
    note: String,
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected', 'paid'],
      default: 'pending'
    },
    decidedAt: Date
  },
  { timestamps: true }
);
txSchema.index(
  { trxId: 1 },
  { unique: true, partialFilterExpression: { trxId: { $type: 'string' } } }
);
const Tx = mongoose.model('Tx', txSchema);

// ---------- হেল্পার ----------
function num(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0 || n > 10000000) return null;
  return Math.round(n * 100) / 100;
}

function clean(v, max) {
  if (v === undefined || v === null) return undefined;
  const s = String(v).trim().slice(0, max || 100);
  return s || undefined;
}

function startOfDhakaDay() {
  const off = 6 * 3600 * 1000;
  const d = new Date(Date.now() + off);
  d.setUTCHours(0, 0, 0, 0);
  return new Date(d.getTime() - off);
}

function escRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function totals(match) {
  const rows = await Tx.aggregate([
    { $match: Object.assign({ status: { $in: ['approved', 'paid'] } }, match || {}) },
    { $group: { _id: '$type', total: { $sum: '$amount' } } }
  ]);
  let dep = 0;
  let pay = 0;
  rows.forEach(function (r) {
    if (r._id === 'deposit') dep = r.total;
    if (r._id === 'payout') pay = r.total;
  });
  return { deposits: dep, payouts: pay };
}

function wrap(fn) {
  return function (req, res) {
    fn(req, res).catch(function (e) {
      console.error(e);
      if (e && e.code === 11000) {
        return res.status(409).json({ ok: false, error: 'এই TrxID আগেই ব্যবহার হয়েছে' });
      }
      res.status(500).json({ ok: false, error: 'সার্ভারে সমস্যা হয়েছে' });
    });
  };
}

// ---------- সাইট API (RS Gallery / RS Matrix এর সার্ভার থেকে কল হবে) ----------
app.post(
  '/api/site/deposit',
  siteAuth,
  wrap(async function (req, res) {
    const amount = num(req.body.amount);
    const trxId = clean(req.body.trxId, 40);
    if (!amount) return res.status(400).json({ ok: false, error: 'সঠিক পরিমাণ দিন' });
    if (!trxId) return res.status(400).json({ ok: false, error: 'TrxID দিন' });
    const tx = await Tx.create({
      type: 'deposit',
      site: req.site,
      amount: amount,
      method: req.body.method === 'nagad' ? 'nagad' : 'bkash',
      number: clean(req.body.number, 20),
      trxId: trxId,
      orderRef: clean(req.body.orderRef, 60),
      status: 'pending'
    });
    res.json({ ok: true, id: tx._id, status: tx.status });
  })
);

app.get(
  '/api/site/status/:trxId',
  siteAuth,
  wrap(async function (req, res) {
    const tx = await Tx.findOne({
      trxId: String(req.params.trxId).toUpperCase(),
      site: req.site
    });
    if (!tx) return res.status(404).json({ ok: false, error: 'পাওয়া যায়নি' });
    res.json({ ok: true, status: tx.status, amount: tx.amount });
  })
);

// ---------- অ্যাডমিন API ----------
app.post('/api/admin/login', function (req, res) {
  const ip = req.ip;
  if (loginBlocked(ip)) {
    return res.status(429).json({ ok: false, error: 'অনেকবার ভুল হয়েছে, ১৫ মিনিট পরে চেষ্টা করুন' });
  }
  if (!req.body.password || !safeEqual(req.body.password, ADMIN_PASSWORD)) {
    loginFail(ip);
    return res.status(401).json({ ok: false, error: 'ভুল পাসওয়ার্ড' });
  }
  attempts.delete(ip);
  res.json({ ok: true, token: signToken() });
});

app.get(
  '/api/admin/summary',
  adminAuth,
  wrap(async function (req, res) {
    const all = await totals();
    const today = startOfDhakaDay();
    const t = await totals({ createdAt: { $gte: today } });
    const gallery = await totals({ site: 'rsgallery' });
    const matrix = await totals({ site: 'rsmatrix' });
    const pending = await Tx.countDocuments({ status: 'pending' });
    res.json({
      ok: true,
      balance: all.deposits - all.payouts,
      totalIn: all.deposits,
      totalOut: all.payouts,
      todayIn: t.deposits,
      todayOut: t.payouts,
      pending: pending,
      sites: {
        rsgallery: gallery.deposits,
        rsmatrix: matrix.deposits
      }
    });
  })
);

app.get(
  '/api/admin/tx',
  adminAuth,
  wrap(async function (req, res) {
    const f = {};
    if (['deposit', 'payout'].includes(req.query.type)) f.type = req.query.type;
    if (['pending', 'approved', 'rejected', 'paid'].includes(req.query.status)) f.status = req.query.status;
    if (['rsgallery', 'rsmatrix', 'manual'].includes(req.query.site)) f.site = req.query.site;
    const q = clean(req.query.q, 40);
    if (q) {
      const rx = new RegExp(escRegex(q), 'i');
      f.$or = [{ trxId: rx }, { number: rx }, { orderRef: rx }, { note: rx }];
    }
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const list = await Tx.find(f).sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ ok: true, list: list });
  })
);

app.post(
  '/api/admin/tx/:id/approve',
  adminAuth,
  wrap(async function (req, res) {
    const tx = await Tx.findOneAndUpdate(
      { _id: req.params.id, type: 'deposit', status: 'pending' },
      { status: 'approved', decidedAt: new Date() },
      { new: true }
    );
    if (!tx) return res.status(409).json({ ok: false, error: 'এটি আগেই প্রসেস হয়েছে বা পাওয়া যায়নি' });
    res.json({ ok: true });
  })
);

app.post(
  '/api/admin/tx/:id/reject',
  adminAuth,
  wrap(async function (req, res) {
    const tx = await Tx.findOneAndUpdate(
      { _id: req.params.id, type: 'deposit', status: 'pending' },
      { status: 'rejected', decidedAt: new Date() },
      { new: true }
    );
    if (!tx) return res.status(409).json({ ok: false, error: 'এটি আগেই প্রসেস হয়েছে বা পাওয়া যায়নি' });
    res.json({ ok: true });
  })
);

// টাকা যোগ (ম্যানুয়াল) — সাথে সাথে অ্যাপ্রুভড
app.post(
  '/api/admin/deposit',
  adminAuth,
  wrap(async function (req, res) {
    const amount = num(req.body.amount);
    if (!amount) return res.status(400).json({ ok: false, error: 'সঠিক পরিমাণ দিন' });
    const site = ['rsgallery', 'rsmatrix', 'manual'].includes(req.body.site) ? req.body.site : 'manual';
    await Tx.create({
      type: 'deposit',
      site: site,
      amount: amount,
      method: req.body.method === 'nagad' ? 'nagad' : 'bkash',
      number: clean(req.body.number, 20),
      trxId: clean(req.body.trxId, 40),
      note: clean(req.body.note, 200),
      status: 'approved',
      decidedAt: new Date()
    });
    res.json({ ok: true });
  })
);

// টাকা পাঠান — তুমি বিকাশ/নগদ থেকে পাঠিয়ে এখানে রেকর্ড করবে
app.post(
  '/api/admin/payout',
  adminAuth,
  wrap(async function (req, res) {
    const amount = num(req.body.amount);
    const number = clean(req.body.number, 20);
    if (!amount) return res.status(400).json({ ok: false, error: 'সঠিক পরিমাণ দিন' });
    if (!number || !/^01\d{9}$/.test(number)) {
      return res.status(400).json({ ok: false, error: 'সঠিক ১১ ডিজিটের নাম্বার দিন' });
    }
    const all = await totals();
    const balance = all.deposits - all.payouts;
    if (amount > balance) {
      return res.status(400).json({ ok: false, error: 'ব্যালেন্স যথেষ্ট নেই। বর্তমান ব্যালেন্স: ' + balance });
    }
    await Tx.create({
      type: 'payout',
      site: 'manual',
      amount: amount,
      method: req.body.method === 'nagad' ? 'nagad' : 'bkash',
      number: number,
      trxId: clean(req.body.trxId, 40),
      note: clean(req.body.note, 200),
      status: 'paid',
      decidedAt: new Date()
    });
    res.json({ ok: true });
  })
);

app.get('/health', function (req, res) {
  res.send('ok');
});

const PORT = process.env.PORT || 3000;
mongoose
  .connect(MONGODB_URI)
  .then(function () {
    app.listen(PORT, function () {
      console.log('RS Wallet running on ' + PORT);
    });
  })
  .catch(function (e) {
    console.error('MongoDB connection failed', e);
    process.exit(1);
  });
