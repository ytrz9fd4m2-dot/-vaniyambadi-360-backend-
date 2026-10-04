const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
});

async function setupDatabase() {
  if (!process.env.DATABASE_URL) {
    console.log("DATABASE_URL is not configured yet.");
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      email TEXT,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'public',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS categories (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      icon TEXT,
      status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS areas (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      district TEXT DEFAULT 'Tirupattur',
      status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS shops (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER REFERENCES users(id),
      name TEXT NOT NULL,
      category_id INTEGER REFERENCES categories(id),
      phone TEXT,
      whatsapp TEXT,
      address TEXT,
      area_id INTEGER REFERENCES areas(id),
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      opening_time TEXT,
      closing_time TEXT,
      weekly_holiday TEXT,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT,
      price NUMERIC,
      offer_price NUMERIC,
      image TEXT,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS shop_photos (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      image_url TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reels (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      video_url TEXT NOT NULL,
      caption TEXT,
      audio_url TEXT,
      whatsapp_enabled BOOLEAN DEFAULT false,
      share_enabled BOOLEAN DEFAULT true,
      download_enabled BOOLEAN DEFAULT false,
      views INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS offers (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT,
      price NUMERIC,
      valid_until DATE,
      image TEXT,
      status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS subscriptions (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      plan_amount NUMERIC DEFAULT 300,
      payment_status TEXT DEFAULT 'pending',
      autopay_status TEXT DEFAULT 'inactive',
      next_payment_date DATE,
      expiry_date DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT,
      message TEXT,
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS saved_items (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      reel_id INTEGER REFERENCES reels(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Database tables are ready.");
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Login required",
    });
  }

  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      message: "Invalid or expired token",
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admin access required",
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    app: "Vaniyambadi 360 Backend",
    status: "running",
    message: "Vaniyambadi 360 API is working",
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "vaniyambadi-360-backend",
  });
});

app.post("/api/auth/register-owner", async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      password,
    } = req.body;

    if (!name || !phone || !password) {
      return res.status(400).json({
        message: "Name, phone and password are required",
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE phone = $1",
      [phone]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        message: "Phone number already registered",
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (name, phone, email, password_hash, role)
      VALUES ($1, $2, $3, $4, 'shop_owner')
      RETURNING id, name, phone, email, role, status
      `,
      [name, phone, email || null, passwordHash]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: "Shop owner registered",
      user,
      token: createToken(user),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Registration failed",
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({
        message: "Phone and password are required",
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE phone = $1",
      [phone]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid phone or password",
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        message: "Invalid phone or password",
      });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        message: "Account is inactive",
      });
    }

    res.json({
      message: "Login successful",
      token: createToken(user),
      user: {
        id: user.id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Login failed",
    });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(
    `
    SELECT id, name, phone, email, role, status, created_at
    FROM users
    WHERE id = $1
    `,
    [req.user.id]
  );

  res.json(result.rows[0]);
});

app.post("/api/shops", auth, async (req, res) => {
  try {
    const {
      name,
      category_id,
      phone,
      whatsapp,
      address,
      area_id,
      latitude,
      longitude,
      opening_time,
      closing_time,
      weekly_holiday,
    } = req.body;

    if (!name) {
      return res.status(400).json({
        message: "Shop name is required",
      });
    }

    const result = await pool.query(
      `
      INSERT INTO shops
      (
        owner_id,
        name,
        category_id,
        phone,
        whatsapp,
        address,
        area_id,
        latitude,
        longitude,
        opening_time,
        closing_time,
        weekly_holiday
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *
      `,
      [
        req.user.id,
        name,
        category_id || null,
        phone || null,
        whatsapp || null,
        address || null,
        area_id || null,
        latitude || null,
        longitude || null,
        opening_time || null,
        closing_time || null,
        weekly_holiday || null,
      ]
    );

    res.status(201).json({
      message: "Shop created",
      shop: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Could not create shop",
    });
  }
});

app.get("/api/shops", async (req, res) => {
  try {
    const { search, area_id, category_id } = req.query;

    let query = `
      SELECT *
      FROM shops
      WHERE status = 'active'
    `;

    const values = [];

    if (search) {
      values.push(`%${search}%`);
      query += ` AND name ILIKE $${values.length}`;
    }

    if (area_id) {
      values.push(area_id);
      query += ` AND area_id = $${values.length}`;
    }

    if (category_id) {
      values.push(category_id);
      query += ` AND category_id = $${values.length}`;
    }

    query += " ORDER BY id DESC";

    const result = await pool.query(query, values);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Could not load shops",
    });
  }
});

app.get("/api/my-shops", auth, async (req, res) => {
  const result = await pool.query(
    `
    SELECT *
    FROM shops
    WHERE owner_id = $1
    ORDER BY id DESC
    `,
    [req.user.id]
  );

  res.json(result.rows);
});

app.put("/api/shops/:shopId", auth, async (req, res) => {
  const shopId = req.params.shopId;

  if (req.user.role !== "admin") {
    const ownerCheck = await pool.query(
      `
      SELECT id
      FROM shops
      WHERE id = $1 AND owner_id = $2
      `,
      [shopId, req.user.id]
    );

    if (ownerCheck.rows.length === 0) {
      return res.status(403).json({
        message: "You can edit only your own shop",
      });
    }
  }

  const {
    name,
    phone,
    whatsapp,
    address,
    opening_time,
    closing_time,
    weekly_holiday,
  } = req.body;

  const result = await pool.query(
    `
    UPDATE shops
    SET
      name = COALESCE($1, name),
      phone = COALESCE($2, phone),
      whatsapp = COALESCE($3, whatsapp),
      address = COALESCE($4, address),
      opening_time = COALESCE($5, opening_time),
      closing_time = COALESCE($6, closing_time),
      weekly_holiday = COALESCE($7, weekly_holiday)
    WHERE id = $8
    RETURNING *
    `,
    [
      name,
      phone,
      whatsapp,
      address,
      opening_time,
      closing_time,
      weekly_holiday,
      shopId,
    ]
  );

  res.json({
    message: "Shop updated",
    shop: result.rows[0],
  });
});

app.post("/api/shops/:shopId/photos", auth, async (req, res) => {
  const shopId = req.params.shopId;

  const ownerCheck = await pool.query(
    `
    SELECT id
    FROM shops
    WHERE id = $1 AND owner_id = $2
    `,
    [shopId, req.user.id]
  );

  if (
    ownerCheck.rows.length === 0 &&
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      message: "You can add photos only to your own shop",
    });
  }

  const { image_url } = req.body;

  if (!image_url) {
    return res.status(400).json({
      message: "image_url is required",
    });
  }

  const result = await pool.query(
    `
    INSERT INTO shop_photos
    (shop_id, image_url)
    VALUES ($1, $2)
    RETURNING *
    `,
    [shopId, image_url]
  );

  res.status(201).json(result.rows[0]);
});

app.get("/api/shops/:shopId/photos", async (req, res) => {
  const result = await pool.query(
    `
    SELECT *
    FROM shop_photos
    WHERE shop_id = $1
    ORDER BY id DESC
    `,
    [req.params.shopId]
  );

  res.json(result.rows);
});

app.post("/api/shops/:shopId/reels", auth, async (req, res) => {
  const shopId = req.params.shopId;

  const ownerCheck = await pool.query(
    `
    SELECT id
    FROM shops
    WHERE id = $1 AND owner_id = $2
    `,
    [shopId, req.user.id]
  );

  if (
    ownerCheck.rows.length === 0 &&
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      message: "You can upload reels only for your own shop",
    });
  }

  const {
    video_url,
    caption,
    audio_url,
    whatsapp_enabled,
    share_enabled,
    download_enabled,
  } = req.body;

  if (!video_url) {
    return res.status(400).json({
      message: "video_url is required",
    });
  }

  const result = await pool.query(
    `
    INSERT INTO reels
    (
      shop_id,
      video_url,
      caption,
      audio_url,
      whatsapp_enabled,
      share_enabled,
      download_enabled
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    RETURNING *
    `,
    [
      shopId,
      video_url,
      caption || null,
      audio_url || null,
      whatsapp_enabled ?? false,
      share_enabled ?? true,
      download_enabled ?? false,
    ]
  );

  res.status(201).json({
    message: "Reel published",
    reel: result.rows[0],
  });
});

app.get("/api/shops/:shopId/reels", async (req, res) => {
  const result = await pool.query(
    `
    SELECT *
    FROM reels
    WHERE shop_id = $1
    AND status = 'active'
    ORDER BY id DESC
    `,
    [req.params.shopId]
  );

  res.json(result.rows);
});

app.get("/api/subscription", auth, async (req, res) => {
  const result = await pool.query(
    `
    SELECT *
    FROM subscriptions
    WHERE owner_id = $1
    ORDER BY id DESC
    LIMIT 1
    `,
    [req.user.id]
  );

  res.json(result.rows[0] || null);
});

app.get("/api/admin/users", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `
    SELECT id, name, phone, email, role, status, created_at
    FROM users
    ORDER BY id DESC
    `
  );

  res.json(result.rows);
});

app.get("/api/admin/shops", auth, adminOnly, async (req, res) => {
  const result = await pool.query(
    `
    SELECT *
    FROM shops
    ORDER BY id DESC
    `
  );

  res.json(result.rows);
});

app.get(
  "/api/admin/subscriptions",
  auth,
  adminOnly,
  async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM subscriptions
      ORDER BY id DESC
      `
    );

    res.json(result.rows);
  }
);

async function startServer() {
  try {
    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Vaniyambadi 360 Backend running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error("Server startup error:", error);
  }
}

startServer();
