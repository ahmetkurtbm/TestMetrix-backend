const express = require("express");
const mysql = require("mysql2/promise");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const cors = require("cors");

const app = express();
const port = 5000;

const JWT_SECRET = "abcdefghjklmnprs";

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3000", // Frontend adresi
    credentials: true, // Cookie gönderimine izin ver
  })
);

// Veritabanı bağlantısı
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "1234",
  database: "tübitak",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Veritabanı yapısını oluşturma (Bir kez çalıştırılır)
(async () => {
  const connection = await pool.getConnection();
  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        surname VARCHAR(50) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        university VARCHAR(100),
        role VARCHAR(50) NOT NULL, -- Yönetici, Öğretmen, Öğrenci
        KVKK TINYINT(1) NOT NULL DEFAULT 0,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS excel_files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        folder_name VARCHAR(100) NOT NULL,
        file_name VARCHAR(100) NOT NULL,
        file_data JSON NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS folders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        folder_name VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Database tables created successfully.");
  } catch (error) {
    console.error("Error creating database tables:", error.message);
  } finally {
    connection.release();
  }
})();

// Kullanıcı işlemleri
app.post("/register", async (req, res) => {
  const { name, surname, email, university, role, KVKK, password } = req.body;

  if (!name || !surname || !email || !password || !role) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.execute(
      "INSERT INTO users (name, surname, email, university, role, KVKK, password ) VALUES (?, ?, ?, ?, ?, ? , ?)",
      [name, surname, email, university, role, KVKK, hashedPassword]
    );

    res.status(201).json({ id: result.insertId, name, surname, email, role });
  } catch (error) {
    console.error("Error registering user:", error.message);
    res.status(500).json({ error: "An error occurred during registration" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  try {
    const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length > 0) {
      const user = rows[0];
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      // JWT token oluşturma
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          name: user.name,
          surname: user.surname,
          university: user.university,
          role: user.role,
        },
        JWT_SECRET,
        { expiresIn: "1h" }
      );

      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 60 * 60 * 1000,
        sameSite: "strict",
      });

      res.status(200).json({ message: "Login successful", token });
    } else {
      res.status(401).json({ error: "Invalid email or password" });
    }
  } catch (error) {
    console.error("Error logging in:", error.message);
    res.status(500).json({ error: "An error occurred during login" });
  }
});

app.get("/user", (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.status(200).json({
      name: decoded.name,
      surname: decoded.surname,
      email: decoded.email,
      university: decoded.university,
    });
  } catch (error) {
    console.error("Error verifying token:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
});

app.put("/user", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Token'ı doğrulama
    const decoded = jwt.verify(token, JWT_SECRET);
    const formData = req.body;

    // Gerekli alanların eksik olup olmadığını kontrol etme
    if (
      !formData.name ||
      !formData.surname ||
      !formData.university ||
      !formData.email ||
      !formData.currentPassword
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Kullanıcının mevcut şifresini veritabanından al
    const [rows] = await pool.execute(
      "SELECT password FROM users WHERE id = ?",
      [decoded.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const hashedPassword = rows[0].password; // Veritabanından alınan mevcut şifre

    // Mevcut şifrenin doğru olup olmadığını kontrol et
    const isMatch = await bcrypt.compare(
      formData.currentPassword,
      hashedPassword
    );

    if (!isMatch) {
      return res.status(400).json({ error: "Current password is incorrect" });
    }

    const newHashedPassword = formData.newPassword
      ? await bcrypt.hash(formData.newPassword, 10) // Yeni şifreyi hash'le
      : hashedPassword;

    // Kullanıcının bilgilerini güncelle
    await pool.execute(
      "UPDATE users SET name = ?, surname = ?, university = ?, email = ?, password = ? WHERE id = ?",
      [
        formData.name,
        formData.surname,
        formData.university,
        formData.email,
        newHashedPassword,
        decoded.id,
      ]
    );

    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error.message);
    res.status(500).json({ error: "An error occurred during user update" });
  }
});

app.delete("/user", async (req, res) => {
  const { id } = req.body;

  try {
    await pool.execute("DELETE FROM users WHERE id = ?", [id]);
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error.message);
    res.status(500).json({ error: "An error occurred during user deletion" });
  }
});

// Excel dosya yükleme işlemleri
const upload = multer({ dest: "uploads/" });

app.post("/excel-upload", upload.single("file"), async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const userId = decoded.id;

    const { folderName, fileName, arrayData } = req.body;

    const [result] = await pool.execute(
      "INSERT INTO excel_files (user_id, folder_name, file_name, file_data) VALUES (?, ?, ?, ?)",
      [userId, folderName, fileName, arrayData]
    );

    res.status(201).json({ id: result.insertId, arrayData });
  } catch (error) {
    console.error("Error uploading Excel file:", error.message);
    res.status(500).json({ error: "An error occurred during Excel upload" });
  }
});

app.get("/folders", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;

    const [rows] = await pool.execute(
      "SELECT id, folder_name, file_name, file_data, created_at FROM excel_files WHERE user_id = ?",
      [userId]
    );

    res.status(200).json(rows);
  } catch (error) {
    console.error("Error fetching folders:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred during fetching folders" });
  }
});

app.post("/excel", async (req, res) => {
  const { fileId } = req.body;

  try {
    const [excel] = await pool.execute(
      "SELECT id, folder_name, file_name, file_data, created_at FROM excel_files WHERE id = ?",
      [fileId]
    );

    res.status(200).json(excel);
  } catch (error) {
    console.error("Error fetching Excel file:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred during fetching Excel file" });
  }
});

app.post("/excel-update", async (req, res) => {
  const { id, folderName, fileName, arrayData } = req.body;

  try {
    // Veritabanında güncelleme sorgusu
    const [result] = await pool.execute(
      "UPDATE excel_files SET folder_name = ?, file_name = ?, file_data = ? WHERE id = ?;",
      [folderName, fileName, JSON.stringify(arrayData), id]
    );

    // Etkilenen satır sayısını kontrol edin
    if (result.affectedRows > 0) {
      res.status(200).json({ message: "Excel file updated successfully" });
    } else {
      res.status(404).json({ error: "Excel file not found" });
    }
  } catch (error) {
    console.error("Error updating Excel file:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred during updating Excel file" });
  }
});

app.post("/excel-update-folder-name", async (req, res) => {
  const { id, folderName } = req.body;

  console.log(typeof id, typeof folderName);

  try {
    // Veritabanında güncelleme sorgusu
    const [result] = await pool.execute(
      "UPDATE excel_files SET folder_name = ? WHERE id = ?;",
      [folderName, id]
    );

    // Etkilenen satır sayısını kontrol edin
    if (result.affectedRows > 0) {
      res.status(200).json({ message: "Excel file updated successfully" });
    } else {
      res.status(404).json({ error: "Excel file not found" });
    }
  } catch (error) {
    console.error("Error updating Excel file:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred during updating Excel file" });
  }
});

app.delete("/excel-delete", async (req, res) => {
  const { fileId } = req.body;
  try {
    await pool.execute("DELETE FROM excel_files WHERE id = ?", [fileId]);
    res.status(200).json({ message: "Excel file deleted successfully" });
  } catch (error) {
    console.error("Error deleting Excel file:", error.message);
    res.status(500).json({ error: "An error occurred during file deletion" });
  }
});

// Klasör işlemleri
// app.post("/folders", async (req, res) => {
//   try {
//     const { folder_name } = req.body;
//     if (!folder_name)
//       return res.status(400).json({ message: "Folder name is required" });
//     const [result] = await connection.query(
//       "INSERT INTO folders (folder_name) VALUES (?)",
//       [folder_name]
//     );
//     res.status(201).json({ id: result.insertId, folder_name });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.get("/folders", async (req, res) => {
//   try {
//     const [rows] = await connection.query("SELECT * FROM folders");
//     res.json(rows);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.get("/folders/:id", async (req, res) => {
//   try {
//     const [rows] = await connection.query(
//       "SELECT * FROM folders WHERE id = ?",
//       [req.params.id]
//     );
//     if (rows.length === 0)
//       return res.status(404).json({ message: "Folder not found" });
//     res.json(rows[0]);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.put("/folders/:id", async (req, res) => {
//   try {
//     const { folder_name } = req.body;
//     if (!folder_name)
//       return res.status(400).json({ message: "Folder name is required" });
//     const [result] = await connection.query(
//       "UPDATE folders SET folder_name = ? WHERE id = ?",
//       [folder_name, req.params.id]
//     );
//     if (result.affectedRows === 0)
//       return res.status(404).json({ message: "Folder not found" });
//     res.json({ message: "Folder updated successfully" });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.delete("/folders/:id", async (req, res) => {
//   try {
//     const [result] = await connection.query(
//       "DELETE FROM folders WHERE id = ?",
//       [req.params.id]
//     );
//     if (result.affectedRows === 0)
//       return res.status(404).json({ message: "Folder not found" });
//     res.json({ message: "Folder deleted successfully" });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// Server başlatma
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
