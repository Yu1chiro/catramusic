require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET wajib diisi minimal 32 karakter. Lihat .env.example.');
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error('DATABASE_URL wajib diisi. Lihat .env.example.');
  process.exit(1);
}

let pool;
if (process.env.NODE_ENV === 'test' && DATABASE_URL === 'pg-mem://test') {
  const { newDb } = require('pg-mem');
  const memoryDatabase = newDb();
  const adapter = memoryDatabase.adapters.createPg();
  pool = new adapter.Pool();
} else {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000
  });
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

// ====== Static assets ======
app.use(express.static(path.join(__dirname, 'public')));

function parseCookies(header = '') {
  return header.split(';').reduce((result, item) => {
    const index = item.indexOf('=');
    if (index < 0) return result;
    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();
    try { result[key] = decodeURIComponent(value); } catch { result[key] = value; }
    return result;
  }, {});
}

function issueToken(admin) {
  return jwt.sign(
    { sub: String(admin.id), username: admin.username, role: 'admin' },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '7d', issuer: 'catra-cms', audience: 'catra-admin' }
  );
}

function setAuthCookie(res, token) {
  const flags = [
    `admin_token=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=604800'
  ];
  if (IS_PRODUCTION) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
}

function requireAuth(req, res, next) {
  const bearer = req.get('authorization')?.startsWith('Bearer ')
    ? req.get('authorization').slice(7)
    : null;
  const token = bearer || parseCookies(req.headers.cookie).admin_token;
  if (!token) return res.status(401).json({ message: 'Silakan masuk sebagai admin.' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'catra-cms',
      audience: 'catra-admin'
    });
    return next();
  } catch {
    return res.status(401).json({ message: 'Sesi tidak valid atau sudah berakhir.' });
  }
}

function requirePageAuth(req, res, next) {
  const token = parseCookies(req.headers.cookie).admin_token;
  if (!token) return res.redirect('/signin');
  try {
    jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'], issuer: 'catra-cms', audience: 'catra-admin'
    });
    return next();
  } catch {
    return res.redirect('/signin');
  }
}

// ====== Page routes (view routes) ======
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/signin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signin.html'));
});

app.get('/admin', requirePageAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

const attempts = new Map();
function authRateLimit(req, res, next) {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const current = attempts.get(key);
  if (!current || current.resetAt <= now) {
    attempts.set(key, { count: 1, resetAt: now + 15 * 60 * 1000 });
    return next();
  }
  if (current.count >= 10) {
    return res.status(429).json({ message: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' });
  }
  current.count += 1;
  next();
}

function cleanText(value, name, max = 120, required = true) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (required && !text) throw new Error(`${name} wajib diisi.`);
  if (text.length > max) throw new Error(`${name} maksimal ${max} karakter.`);
  return text;
}

function cleanYear(value) {
  const year = Number(value);
  if (!Number.isInteger(year) || year < 1900 || year > 2100) {
    throw new Error('Tahun harus berupa angka 1900–2100.');
  }
  return year;
}

function cleanUrl(value, name, required = true) {
  const raw = cleanText(value, name, 2048, required);
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error();
    return url.href;
  } catch {
    throw new Error(`${name} harus berupa URL http/https yang valid.`);
  }
}

function cleanWebpUrl(value) {
  const href = cleanUrl(value, 'URL gambar WebP');
  const url = new URL(href);
  if (!url.pathname.toLowerCase().endsWith('.webp')) {
    throw new Error('Setiap gambar gallery wajib berekstensi .webp.');
  }
  return href;
}

function cleanDescription(value) {
  const raw = typeof value === 'string' ? value : '';
  if (raw.length > 20_000) throw new Error('Description maksimal 20.000 karakter.');
  return sanitizeHtml(raw, {
    allowedTags: ['p', 'br', 'strong', 'em', 'u', 'blockquote', 'ol', 'ul', 'li', 'h2', 'h3', 'a'],
    allowedAttributes: { a: ['href', 'target', 'rel'] },
    allowedSchemes: ['http', 'https', 'mailto'],
    transformTags: {
      a: (tagName, attribs) => ({
        tagName,
        attribs: { ...attribs, target: '_blank', rel: 'noopener noreferrer' }
      })
    }
  }).trim() || null;
}

function parseId(req, res) {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) {
    res.status(400).json({ message: 'ID tidak valid.' });
    return null;
  }
  return id;
}

function validationError(res, error) {
  return res.status(400).json({ message: error.message || 'Data tidak valid.' });
}

app.post('/api/auth/register', authRateLimit, async (req, res, next) => {
  try {
    const username = cleanText(req.body.username, 'Username', 32).toLowerCase();
    const email = cleanText(req.body.email, 'Email', 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!/^[a-z0-9_]{3,32}$/.test(username)) {
      return validationError(res, new Error('Username 3–32 karakter: huruf kecil, angka, atau underscore.'));
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return validationError(res, new Error('Format email tidak valid.'));
    }
    if (password.length < 8 || password.length > 72) {
      return validationError(res, new Error('Password harus 8–72 karakter.'));
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO admins (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, passwordHash]
    );
    attempts.delete(req.ip);
    setAuthCookie(res, issueToken(rows[0]));
    return res.status(201).json({ message: 'Akun admin berhasil dibuat.', user: rows[0] });
  } catch (error) {
    if (error.message?.includes('wajib') || error.message?.includes('maksimal')) return validationError(res, error);
    if (error.code === '23505') return res.status(409).json({ message: 'Username atau email sudah digunakan.' });
    return next(error);
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res, next) => {
  try {
    const username = cleanText(req.body.username, 'Username', 32).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const { rows } = await pool.query(
      'SELECT id, username, email, password_hash FROM admins WHERE LOWER(username) = LOWER($1) LIMIT 1',
      [username]
    );
    const valid = rows[0] && await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ message: 'Username atau password salah.' });
    attempts.delete(req.ip);
    setAuthCookie(res, issueToken(rows[0]));
    return res.json({ message: 'Berhasil masuk.', user: { id: rows[0].id, username: rows[0].username, email: rows[0].email } });
  } catch (error) {
    if (error.message?.includes('wajib') || error.message?.includes('maksimal')) return validationError(res, error);
    return next(error);
  }
});

app.get('/api/auth/me', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT id, username, email FROM admins WHERE id = $1', [req.admin.sub]);
    if (!rows[0]) return res.status(401).json({ message: 'Akun tidak ditemukan.' });
    return res.json({ user: rows[0] });
  } catch (error) { return next(error); }
});

app.post('/api/auth/logout', (req, res) => {
  const flags = ['admin_token=', 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (IS_PRODUCTION) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
  res.json({ message: 'Berhasil keluar.' });
});

// ====== PUBLIC API ======
app.get('/api/discography', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT id, title, image_url, type, year, spotify_url, soundcloud_url FROM discographies ORDER BY year DESC, created_at DESC');
    res.json({ data: rows });
  } catch (error) { next(error); }
});

app.get('/api/works', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 6, 1), 100);
    const { rows } = await pool.query('SELECT id, title, image_url, category, year, description FROM selected_works ORDER BY year DESC, created_at DESC LIMIT $1', [limit]);
    res.json({ data: rows });
  } catch (error) { next(error); }
});

app.get('/api/gallery', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 6, 1), 100);
    const { rows } = await pool.query(
      `SELECT gi.id, gi.gallery_id, g.title, g.year, gi.image_url
       FROM gallery_images gi
       JOIN galleries g ON g.id = gi.gallery_id
       ORDER BY g.year DESC, g.created_at DESC, gi.position ASC, gi.id ASC
       LIMIT $1`,
      [limit]
    );
    res.json({ data: rows });
  } catch (error) { next(error); }
});

// PUBLIC MUSIC (Untuk Bubble Player)
app.get('/api/musics', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT title, thumbnail_url, mp3_url FROM musics ORDER BY created_at DESC LIMIT 1');
    res.json({ data: rows[0] || null });
  } catch (error) { next(error); }
});

// PUBLIC ABOUT SECTION
app.get('/api/about', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT content FROM about_section WHERE id = 1');
    res.json({ data: rows[0] || null });
  } catch (error) { next(error); }
});

// ====== ADMIN API ======
app.use('/api/admin', requireAuth);

// Admin Discography
app.get('/api/admin/discography', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT * FROM discographies ORDER BY created_at DESC');
    res.json({ data: rows });
  } catch (error) { next(error); }
});

app.post('/api/admin/discography', async (req, res, next) => {
  try {
    const values = [
      cleanText(req.body.title, 'Title'), cleanUrl(req.body.image_url, 'URL image'),
      cleanText(req.body.type, 'Type', 10), cleanYear(req.body.year),
      cleanUrl(req.body.spotify_url, 'Link Spotify'), cleanUrl(req.body.soundcloud_url, 'Link SoundCloud')
    ];
    if (!['album', 'single'].includes(values[2])) throw new Error('Type harus album atau single.');
    const { rows } = await pool.query(
      `INSERT INTO discographies (title, image_url, type, year, spotify_url, soundcloud_url)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`, values
    );
    res.status(201).json({ message: 'Discography berhasil ditambahkan.', data: rows[0] });
  } catch (error) { if (!error.code) return validationError(res, error); next(error); }
});

app.put('/api/admin/discography/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  try {
    const values = [
      cleanText(req.body.title, 'Title'), cleanUrl(req.body.image_url, 'URL image'),
      cleanText(req.body.type, 'Type', 10), cleanYear(req.body.year),
      cleanUrl(req.body.spotify_url, 'Link Spotify'), cleanUrl(req.body.soundcloud_url, 'Link SoundCloud'), id
    ];
    if (!['album', 'single'].includes(values[2])) throw new Error('Type harus album atau single.');
    const { rows } = await pool.query(
      `UPDATE discographies SET title=$1,image_url=$2,type=$3,year=$4,spotify_url=$5,soundcloud_url=$6,updated_at=NOW()
       WHERE id=$7 RETURNING *`, values
    );
    if (!rows[0]) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ message: 'Discography berhasil diperbarui.', data: rows[0] });
  } catch (error) { if (!error.code) return validationError(res, error); next(error); }
});

app.delete('/api/admin/discography/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  try {
    const result = await pool.query('DELETE FROM discographies WHERE id=$1', [id]);
    if (!result.rowCount) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ message: 'Discography berhasil dihapus.' });
  } catch (error) { next(error); }
});

// Admin Works
app.get('/api/admin/works', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT * FROM selected_works ORDER BY created_at DESC');
    res.json({ data: rows });
  } catch (error) { next(error); }
});

function parseWork(body) {
  const category = cleanText(body.category, 'Kategori', 10);
  if (!['video', 'music', 'photo', 'album'].includes(category)) throw new Error('Kategori tidak valid.');
  return [
    cleanText(body.title, 'Title'), cleanUrl(body.image_url, 'URL image', false),
    category, cleanYear(body.year), cleanDescription(body.description)
  ];
}

app.post('/api/admin/works', async (req, res, next) => {
  try {
    const values = parseWork(req.body);
    const { rows } = await pool.query(
      `INSERT INTO selected_works (title,image_url,category,year,description)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`, values
    );
    res.status(201).json({ message: 'Selected work berhasil ditambahkan.', data: rows[0] });
  } catch (error) { if (!error.code) return validationError(res, error); next(error); }
});

app.put('/api/admin/works/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  try {
    const values = [...parseWork(req.body), id];
    const { rows } = await pool.query(
      `UPDATE selected_works SET title=$1,image_url=$2,category=$3,year=$4,description=$5,updated_at=NOW()
       WHERE id=$6 RETURNING *`, values
    );
    if (!rows[0]) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ message: 'Selected work berhasil diperbarui.', data: rows[0] });
  } catch (error) { if (!error.code) return validationError(res, error); next(error); }
});

app.delete('/api/admin/works/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  try {
    const result = await pool.query('DELETE FROM selected_works WHERE id=$1', [id]);
    if (!result.rowCount) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ message: 'Selected work berhasil dihapus.' });
  } catch (error) { next(error); }
});

// Admin Gallery
async function getAdminGalleries() {
  const { rows } = await pool.query(
    `SELECT g.id, g.title, g.year, g.created_at, g.updated_at,
      COALESCE(json_agg(json_build_object('id', gi.id, 'image_url', gi.image_url, 'position', gi.position)
        ORDER BY gi.position, gi.id) FILTER (WHERE gi.id IS NOT NULL), '[]') AS images
     FROM galleries g LEFT JOIN gallery_images gi ON gi.gallery_id = g.id
     GROUP BY g.id ORDER BY g.created_at DESC`
  );
  return rows;
}

app.get('/api/admin/gallery', async (req, res, next) => {
  try { res.json({ data: await getAdminGalleries() }); } catch (error) { next(error); }
});

function parseGallery(body) {
  const title = cleanText(body.title, 'Title');
  const year = cleanYear(body.year);
  if (!Array.isArray(body.images) || body.images.length < 1 || body.images.length > 30) {
    throw new Error('Gallery memerlukan 1–30 URL gambar WebP.');
  }
  return { title, year, images: body.images.map(cleanWebpUrl) };
}

app.post('/api/admin/gallery', async (req, res, next) => {
  const client = await pool.connect();
  try {
    const data = parseGallery(req.body);
    await client.query('BEGIN');
    const { rows } = await client.query('INSERT INTO galleries (title,year) VALUES ($1,$2) RETURNING *', [data.title, data.year]);
    for (let index = 0; index < data.images.length; index += 1) {
      await client.query('INSERT INTO gallery_images (gallery_id,image_url,position) VALUES ($1,$2,$3)', [rows[0].id, data.images[index], index]);
    }
    await client.query('COMMIT');
    res.status(201).json({ message: 'Gallery berhasil ditambahkan.', data: rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    if (!error.code) return validationError(res, error);
    next(error);
  } finally { client.release(); }
});

app.put('/api/admin/gallery/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  const client = await pool.connect();
  try {
    const data = parseGallery(req.body);
    await client.query('BEGIN');
    const result = await client.query('UPDATE galleries SET title=$1,year=$2,updated_at=NOW() WHERE id=$3 RETURNING *', [data.title, data.year, id]);
    if (!result.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Data tidak ditemukan.' });
    }
    await client.query('DELETE FROM gallery_images WHERE gallery_id=$1', [id]);
    for (let index = 0; index < data.images.length; index += 1) {
      await client.query('INSERT INTO gallery_images (gallery_id,image_url,position) VALUES ($1,$2,$3)', [id, data.images[index], index]);
    }
    await client.query('COMMIT');
    res.json({ message: 'Gallery berhasil diperbarui.', data: result.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    if (!error.code) return validationError(res, error);
    next(error);
  } finally { client.release(); }
});

app.delete('/api/admin/gallery/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  try {
    const result = await pool.query('DELETE FROM galleries WHERE id=$1', [id]);
    if (!result.rowCount) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ message: 'Gallery berhasil dihapus.' });
  } catch (error) { next(error); }
});

// Admin Music Player
app.get('/api/admin/musics', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT * FROM musics ORDER BY created_at DESC');
    res.json({ data: rows });
  } catch (error) { next(error); }
});

app.post('/api/admin/musics', async (req, res, next) => {
  try {
    const values = [
      cleanText(req.body.title, 'Title'),
      cleanUrl(req.body.thumbnail_url, 'Thumbnail URL', false),
      cleanUrl(req.body.mp3_url, 'MP3 URL')
    ];
    const { rows } = await pool.query(
      `INSERT INTO musics (title, thumbnail_url, mp3_url) VALUES ($1,$2,$3) RETURNING *`, values
    );
    res.status(201).json({ message: 'Music berhasil ditambahkan.', data: rows[0] });
  } catch (error) { if (!error.code) return validationError(res, error); next(error); }
});

app.put('/api/admin/musics/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  try {
    const values = [
      cleanText(req.body.title, 'Title'),
      cleanUrl(req.body.thumbnail_url, 'Thumbnail URL', false),
      cleanUrl(req.body.mp3_url, 'MP3 URL'), id
    ];
    const { rows } = await pool.query(
      `UPDATE musics SET title=$1, thumbnail_url=$2, mp3_url=$3, updated_at=NOW() WHERE id=$4 RETURNING *`, values
    );
    if (!rows[0]) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ message: 'Music berhasil diperbarui.', data: rows[0] });
  } catch (error) { if (!error.code) return validationError(res, error); next(error); }
});

app.delete('/api/admin/musics/:id', async (req, res, next) => {
  const id = parseId(req, res); if (!id) return;
  try {
    const result = await pool.query('DELETE FROM musics WHERE id=$1', [id]);
    if (!result.rowCount) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ message: 'Music berhasil dihapus.' });
  } catch (error) { next(error); }
});

// Admin About Section
app.get('/api/admin/about', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT content FROM about_section WHERE id = 1');
    res.json({ data: rows[0] || { content: '' } });
  } catch (error) { next(error); }
});

app.put('/api/admin/about', async (req, res, next) => {
  try {
    const content = cleanDescription(req.body.content);
    const { rows } = await pool.query(
      `UPDATE about_section SET content=$1, updated_at=NOW() WHERE id=1 RETURNING content`, [content]
    );
    res.json({ message: 'About section berhasil diperbarui.', data: rows[0] });
  } catch (error) { if (!error.code) return validationError(res, error); next(error); }
});

app.use('/api', (req, res) => res.status(404).json({ message: 'Endpoint tidak ditemukan.' }));
app.use((error, req, res, next) => {
  console.error(`[${new Date().toISOString()}]`, error);
  if (res.headersSent) return next(error);
  res.status(500).json({ message: 'Terjadi kesalahan pada server.' });
});

async function start() {
  await pool.query(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  app.listen(PORT, () => console.log(`Catra CMS berjalan di http://localhost:${PORT}`));
}

if (require.main === module) {
  start().catch((error) => {
    console.error('Gagal menjalankan server:', error.message);
    process.exit(1);
  });
}

module.exports = app;