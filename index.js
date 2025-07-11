// src/index.js

// 環境に応じて .env.development / .env.production を読み分け
const envFile = process.env.NODE_ENV === "production"
  ? ".env.production"
  : ".env.development";
require("dotenv").config({ path: envFile });

const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const saltRounds = 10;
const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key";

// 環境変数から ALLOWED_ORIGINS を読み込む
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// CORS設定
if (process.env.NODE_ENV === "development") {
  // 開発中はすべてのオリジンを許可（ホットリロード用）
  app.use(cors());
} else {
  // 本番環境は ALLOWED_ORIGINS のみ許可
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      callback(new Error("Not allowed by CORS"));
    }
  }));
}

app.use(bodyParser.json());

// MySQL接続設定
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

db.getConnection(err => {
  if (err) {
    console.error("Error connecting to MySQL: ", err);
    return;
  }
  console.log("Connected to MySQL");
});

// 認証ミドルウェア: Authorization ヘッダーから JWT を取得
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization header missing or invalid' });
  }
  const token = authHeader.slice(7);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// サーバー起動前のルート定義
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// ユーザー登録
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    db.query(
      'INSERT INTO users (email, password) VALUES (?, ?)',
      [email, hash],
      err => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Error registering user' });
        }
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  } catch (e) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ログイン: JWT を JSON で返却
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Internal server error' });
    if (results.length === 0) return res.status(401).json({ message: 'Invalid email or password' });

    const user = results[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      SECRET_KEY,
      { expiresIn: '1h' }
    );
    res.json({ message: 'Login successful', token });
  });
});

// ログアウト: クライアント側でトークンをクリア
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// 認証が必要なルート
app.get('/api/user', authenticateToken, (req, res) => {
  db.query(
    'SELECT id, email FROM users WHERE id = ?',
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Internal server error' });
      res.json(results[0]);
    }
  );
});

app.get('/api/checklist', authenticateToken, (req, res) => {
    // ?facility=galleria もしくは terrace
    const facility = req.query.facility || 'galleria';
    db.query(
      'SELECT * FROM checklist_items WHERE facility = ?',
      [facility],
      (err, results) => {
    if (err) return res.status(500).json({ message: 'Internal server error' });
    res.json(results);
  });
});

app.post('/api/checklist', authenticateToken, (req, res) => {
    // name と facility（なければ galleria をデフォルト）
    const { name, facility = 'galleria' } = req.body;
  if (!name) return res.status(400).json({ message: 'Name is required' });
  // facility を 2 番目のカラムに追加
  const vals = [
      name,
      facility,
      false, false, false, false,
      false, false, false, false,
      false, false, false
    ];
    db.query(
      `INSERT INTO checklist_items
        (name, facility,
         checked_out, bussing, amenities, washing,
         bed_making, bath_toilet, vacuum, finishing,
         final_check, stayed, today_used)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      vals,
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Internal server error' });
      res.status(201).json({
        id: result.insertId,
        name,
        facility,
        checked_out: false,
        bussing: false,
        amenities: false,
        washing: false,
        bed_making: false,
        bath_toilet: false,
        vacuum: false,
        finishing: false,
        final_check: false,
        stayed: false,
        today_used: false
      });
    }
  );
});

app.put('/api/checklist/update-field/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { field, value } = req.body;
  const validFields = [
        'stayed','checked_out','bussing','amenities','washing',
        'bed_making','bath_toilet','vacuum','finishing',
        'sheets','onsen_start','onsen_stop',
        'final_check','today_used'
      ];
  if (!validFields.includes(field)) {
    return res.status(400).json({ message: 'Invalid field name' });
  }
  if (typeof value !== 'boolean') {
    return res.status(400).json({ message: 'Value must be a boolean' });
  }
  db.query(
    `UPDATE checklist_items SET \`${field}\` = ? WHERE id = ?`,
    [value, id],
    err => {
      if (err) return res.status(500).json({ message: 'Internal server error' });
      res.sendStatus(200);
    }
  );
});

// サーバー起動
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});

