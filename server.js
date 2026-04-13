const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// KEAMANAN: Proteksi header
app.use(helmet());

const rateLimit = require('express-rate-limit');

// Rate limiting untuk semua request
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Terlalu banyak request, coba lagi nanti' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Terlalu banyak percobaan login, coba lagi nanti' },
});

app.use(globalLimiter);
app.use('/admin/', authLimiter);
app.use('/api/login', authLimiter);

app.use(cors({
    origin: ['https://albian-persada-teknik.vercel.app', 'http://localhost:3000'],
    optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/data', (req, res) => {
    res.status(403).json({ error: 'Akses ditolak' });
});

const DATA_DIR = path.join(__dirname, 'data');

// File database LENGKAP dengan pemasukan
const files = {
  proyek: path.join(DATA_DIR, 'proyek.json'),
  kontak: path.join(DATA_DIR, 'kontak.json'),
  users: path.join(DATA_DIR, 'users.json'),
  stok: path.join(DATA_DIR, 'stok.json'),
  cabang: path.join(DATA_DIR, 'cabang.json'),
  pemasukan: path.join(DATA_DIR, 'pemasukan.json')
};

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const hashedPassword = '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrZQ5N5g7E6jR7X8Y9zA1b2C3d4E5fG';

const defaultData = {
  proyek: [
    {"id": 1, "nama": "Pak M. Yulfan", "jenis": "Semi Overflow", "ukuran": "4m × 7m", "lokasi": "G.N. Bandar, Bogor", "status": "Selesai", "nilai": 45000000},
    {"id": 2, "nama": "Pak Ruli", "jenis": "Semi Overflow", "ukuran": "4m × 3m", "lokasi": "-", "status": "Selesai", "nilai": 35000000},
    {"id": 3, "nama": "Ibu Hikmah", "jenis": "Semi Overflow", "ukuran": "7m × 3m", "lokasi": "Cilodong", "status": "Selesai", "nilai": 55000000}
  ],
  kontak: [],
  users: [
    {"id": 1, "username": "admin", "password": hashedPassword, "role": "admin"}
  ],
  stok: [
    {"id": 1, "nama": "Keramik Roman 30x30", "kategori": "Keramik", "hargaJual": 197500, "stok": 50, "satuan": "box", "cabangId": 1},
    {"id": 2, "nama": "Pompa Max E Pro 1HP", "kategori": "Pompa", "hargaJual": 12129000, "stok": 5, "satuan": "unit", "cabangId": 1},
    {"id": 3, "nama": "Jasa Pasang Pompa", "kategori": "Jasa", "hargaJual": 2500000, "stok": 999, "satuan": "paket", "cabangId": 1}
  ],
  cabang: [
    {"id": 1, "nama": "Kantor Pusat Parung", "alamat": "Kampung Lebak Wangi, Pemagarsari, Parung, Bogor", "telepon": "(021) 77974824", "wa": "6281291565358", "jamOperasional": "Senin-Sabtu: 08:00-17:00"},
    {"id": 2, "nama": "Albian Pool Shop Sawangan", "alamat": "Jl. Raya Sawangan Depok No.10, Pancoran Mas, Depok", "telepon": "081291565358", "wa": "6281291565358", "jamOperasional": "Senin-Minggu: 08:00-20:00"},
    {"id": 3, "nama": "Smart Pool Ciawi", "alamat": "Jl. Raya Nusantara Sukabumi Km.2, Ciawi Bogor", "telepon": "081280865475", "wa": "6281280865475", "jamOperasional": "Senin-Sabtu: 08:00-18:00"}
  ],
  pemasukan: [
    {"id": 1, "kategori": "Jasa Konstruksi", "nominal": 135000000, "tanggal": "2026-04-01", "keterangan": "Proyek Pak Yulfan, Ruli, Hikmah"},
    {"id": 2, "kategori": "Penjualan Produk", "nominal": 50000000, "tanggal": "2026-04-01", "keterangan": "Penjualan dari Tokopedia"},
    {"id": 3, "kategori": "Maintenance", "nominal": 10000000, "tanggal": "2026-04-05", "keterangan": "Langganan bulan Maret"},
    {"id": 4, "kategori": "Konsultasi", "nominal": 5000000, "tanggal": "2026-04-10", "keterangan": "Konsultasi online"}
  ]
};

Object.keys(files).forEach(key => {
  if (!fs.existsSync(files[key])) {
    fs.writeFileSync(files[key], JSON.stringify(defaultData[key] || [], null, 2));
  }
});

const readJSON = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const writeJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

function auth(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized - Token required' });
    }
    const token = authHeader.split(' ')[1];
    if (token !== 'rahasia123') {
        return res.status(403).json({ error: 'Forbidden - Invalid token' });
    }
    next();
}

// ============= API LOGIN =============
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(files.users);
  const user = users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
  } else {
    res.status(401).json({ success: false, message: 'Username atau password salah' });
  }
});

// ============= API PROYEK =============
app.get('/api/proyek', (req, res) => res.json(readJSON(files.proyek)));
app.post('/api/proyek', auth, (req, res) => {
  const proyek = readJSON(files.proyek);
  const newProyek = { id: Date.now(), ...req.body };
  proyek.push(newProyek);
  writeJSON(files.proyek, proyek);
  res.json({ success: true, data: newProyek });
});
app.put('/api/proyek/:id', auth, (req, res) => {
  const proyek = readJSON(files.proyek);
  const index = proyek.findIndex(p => p.id == req.params.id);
  if (index !== -1) {
    proyek[index] = { ...proyek[index], ...req.body };
    writeJSON(files.proyek, proyek);
    res.json({ success: true });
  } else res.status(404).json({ success: false });
});
app.delete('/api/proyek/:id', auth, (req, res) => {
  const proyek = readJSON(files.proyek);
  writeJSON(files.proyek, proyek.filter(p => p.id != req.params.id));
  res.json({ success: true });
});

// ============= API STOK =============
app.get('/api/stok', (req, res) => res.json(readJSON(files.stok)));
app.post('/api/stok', auth, (req, res) => {
  const stok = readJSON(files.stok);
  const newStok = { id: Date.now(), ...req.body };
  stok.push(newStok);
  writeJSON(files.stok, stok);
  res.json({ success: true });
});
app.put('/api/stok/:id', auth, (req, res) => {
  const stok = readJSON(files.stok);
  const index = stok.findIndex(s => s.id == req.params.id);
  if (index !== -1) {
    stok[index] = { ...stok[index], ...req.body };
    writeJSON(files.stok, stok);
    res.json({ success: true });
  } else res.status(404).json({ success: false });
});
app.delete('/api/stok/:id', auth, (req, res) => {
  const stok = readJSON(files.stok);
  writeJSON(files.stok, stok.filter(s => s.id != req.params.id));
  res.json({ success: true });
});

// ============= API CABANG =============
app.get('/api/cabang', (req, res) => res.json(readJSON(files.cabang)));
app.post('/api/cabang', auth, (req, res) => {
  const cabang = readJSON(files.cabang);
  const newCabang = { id: Date.now(), ...req.body };
  cabang.push(newCabang);
  writeJSON(files.cabang, cabang);
  res.json({ success: true });
});
app.put('/api/cabang/:id', auth, (req, res) => {
  const cabang = readJSON(files.cabang);
  const index = cabang.findIndex(c => c.id == req.params.id);
  if (index !== -1) {
    cabang[index] = { ...cabang[index], ...req.body };
    writeJSON(files.cabang, cabang);
    res.json({ success: true });
  } else res.status(404).json({ success: false });
});
app.delete('/api/cabang/:id', auth, (req, res) => {
  const cabang = readJSON(files.cabang);
  writeJSON(files.cabang, cabang.filter(c => c.id != req.params.id));
  res.json({ success: true });
});

// ============= API PEMASUKAN =============
app.get('/api/pemasukan', (req, res) => res.json(readJSON(files.pemasukan)));
app.post('/api/pemasukan', auth, (req, res) => {
  const pemasukan = readJSON(files.pemasukan);
  const newPemasukan = { id: Date.now(), ...req.body };
  pemasukan.push(newPemasukan);
  writeJSON(files.pemasukan, pemasukan);
  res.json({ success: true, data: newPemasukan });
});
app.put('/api/pemasukan/:id', auth, (req, res) => {
  const pemasukan = readJSON(files.pemasukan);
  const index = pemasukan.findIndex(p => p.id == req.params.id);
  if (index !== -1) {
    pemasukan[index] = { ...pemasukan[index], ...req.body };
    writeJSON(files.pemasukan, pemasukan);
    res.json({ success: true });
  } else res.status(404).json({ success: false });
});
app.delete('/api/pemasukan/:id', auth, (req, res) => {
  const pemasukan = readJSON(files.pemasukan);
  writeJSON(files.pemasukan, pemasukan.filter(p => p.id != req.params.id));
  res.json({ success: true });
});

// ============= API KONTAK =============
app.post('/api/kontak', (req, res) => {
  const kontak = readJSON(files.kontak);
  const newKontak = { id: Date.now(), ...req.body, tanggal: new Date().toISOString() };
  kontak.push(newKontak);
  writeJSON(files.kontak, kontak);
  res.json({ success: true });
});

// ============= API DASHBOARD =============
app.get('/api/dashboard', (req, res) => {
  const proyek = readJSON(files.proyek);
  const stok = readJSON(files.stok);
  const cabang = readJSON(files.cabang);
  const pemasukan = readJSON(files.pemasukan);
  const totalPemasukan = pemasukan.reduce((sum, p) => sum + (p.nominal || 0), 0);
  res.json({
    totalProyek: proyek.length,
    proyekSelesai: proyek.filter(p => p.status === 'Selesai').length,
    totalStok: stok.reduce((sum, s) => sum + s.stok, 0),
    totalCabang: cabang.length,
    totalPemasukan: totalPemasukan
  });
});

// ============= FALLBACK =============
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============= START SERVER =============
app.listen(PORT, '0.0.0.0', () => {
  console.log('🔒 ALBIAN PERSADA TEKNIK - Server berjalan di http://localhost:' + PORT);
  console.log('✅ API: Proyek | Stok | Cabang | Pemasukan | Kontak | Dashboard');
});
