const express = require("express");
const mysql = require("mysql2/promise");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();
const port = 5000;

const JWT_SECRET = "abcdefghjklmnprs";
const uri =
  "mongodb+srv://tubitak-admin:uFt7yIN9j8zaE4su@cluster0.x2r3tsi.mongodb.net/tubitak?retryWrites=true&w=majority&appName=Cluster0";

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

mongoose
  .connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB!"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  surname: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  university: { type: String },
  role: { type: String, required: true }, // Yönetici, Öğretmen, Öğrenci
  KVKK: { type: Boolean, default: false },
  password: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// Excel Files Schema
const excelFileSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  folder_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Folder",
    required: true,
  },
  file_name: { type: String, required: true },
  file_data: { type: Object, required: true },
  created_at: { type: Date, default: Date.now },
});
const ExcelFile = mongoose.model("ExcelFile", excelFileSchema);

// Folder Schema
const folderSchema = new mongoose.Schema({
  folder_name: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});
const Folder = mongoose.model("Folder", folderSchema);

console.log("Schemas created successfully.");

// Veritabanı bağlantısı
// const pool = mysql.createPool({
//   host: "localhost",
//   user: "root",
//   password: "1234",
//   database: "tübitak",
//   waitForConnections: true,
//   connectionLimit: 10,
//   queueLimit: 0,
// });

// Veritabanı yapısını oluşturma (Bir kez çalıştırılır)
// (async () => {
//   const connection = await pool.getConnection();
//   try {
//     await connection.query(`
//       CREATE TABLE IF NOT EXISTS users (
//         id INT AUTO_INCREMENT PRIMARY KEY,
//         name VARCHAR(50) NOT NULL,
//         surname VARCHAR(50) NOT NULL,
//         email VARCHAR(100) UNIQUE NOT NULL,
//         university VARCHAR(100),
//         role VARCHAR(50) NOT NULL, -- Yönetici, Öğretmen, Öğrenci
//         KVKK TINYINT(1) NOT NULL DEFAULT 0,
//         password VARCHAR(100) NOT NULL,
//         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//       );
//     `);

//     await connection.query(`
//       CREATE TABLE IF NOT EXISTS excel_files (
//         id INT AUTO_INCREMENT PRIMARY KEY,
//         user_id INT NOT NULL,
//         folder_id INT NOT NULL,
//         file_name VARCHAR(100) NOT NULL,
//         file_data JSON NOT NULL,
//         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//         FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
//       );
//     `);

//     await connection.query(`
//       CREATE TABLE IF NOT EXISTS folders (
//         id INT AUTO_INCREMENT PRIMARY KEY,
//         folder_name VARCHAR(50) NOT NULL,
//         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//       );
//     `);

//     console.log("Database tables created successfully.");
//   } catch (error) {
//     console.error("Error creating database tables:", error.message);
//   } finally {
//     connection.release();
//   }
// })();

// Kullanıcı işlemleri
// app.post("/register", async (req, res) => {
//   const { name, surname, email, university, role, KVKK, password } = req.body;

//   if (!name || !surname || !email || !password || !role) {
//     return res.status(400).json({ error: "Missing required fields" });
//   }

//   try {
//     const hashedPassword = await bcrypt.hash(password, 10);

//     const [result] = await pool.execute(
//       "INSERT INTO users (name, surname, email, university, role, KVKK, password ) VALUES (?, ?, ?, ?, ?, ? , ?)",
//       [name, surname, email, university, role, KVKK, hashedPassword]
//     );

//     res.status(201).json({ id: result.insertId, name, surname, email, role });
//   } catch (error) {
//     console.error("Error registering user:", error.message);
//     res.status(500).json({ error: "An error occurred during registration" });
//   }
// });

// app.post("/login", async (req, res) => {
//   const { email, password } = req.body;

//   if (!email || !password) {
//     return res.status(400).json({ error: "Missing email or password" });
//   }

//   try {
//     const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [
//       email,
//     ]);

//     if (rows.length > 0) {
//       const user = rows[0];
//       const isPasswordValid = await bcrypt.compare(password, user.password);

//       if (!isPasswordValid) {
//         return res.status(401).json({ error: "Invalid email or password" });
//       }

//       // JWT token oluşturma
//       const token = jwt.sign(
//         {
//           id: user.id,
//           email: user.email,
//           name: user.name,
//           surname: user.surname,
//           university: user.university,
//           role: user.role,
//         },
//         JWT_SECRET,
//         { expiresIn: "1h" }
//       );

//       res.cookie("token", token, {
//         httpOnly: true,
//         secure: process.env.NODE_ENV === "production",
//         maxAge: 60 * 60 * 1000,
//         sameSite: "strict",
//       });

//       res.status(200).json({ message: "Login successful", token });
//     } else {
//       res.status(401).json({ error: "Invalid email or password" });
//     }
//   } catch (error) {
//     console.error("Error logging in:", error.message);
//     res.status(500).json({ error: "An error occurred during login" });
//   }
// });
// Register User
app.post("/register", async (req, res) => {
  try {
    const { name, surname, email, university, role, KVKK, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      surname,
      email,
      university,
      role,
      KVKK,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login User
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    res
      .cookie("token", token, { httpOnly: true })
      .json({ message: "Login successful" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// app.get("/user", (req, res) => {
//   const token = req.cookies.token;

//   if (!token) {
//     return res.status(401).json({ error: "Unauthorized" });
//   }

//   try {
//     const decoded = jwt.verify(token, JWT_SECRET);
//     res.status(200).json({
//       name: decoded.name,
//       surname: decoded.surname,
//       email: decoded.email,
//       university: decoded.university,
//     });
//   } catch (error) {
//     console.error("Error verifying token:", error.message);
//     res.status(401).json({ error: "Invalid token" });
//   }
// });

// app.put("/user", async (req, res) => {
//   const token = req.cookies.token;

//   if (!token) {
//     return res.status(401).json({ error: "Unauthorized" });
//   }

//   try {
//     // Token'ı doğrulama
//     const decoded = jwt.verify(token, JWT_SECRET);
//     const formData = req.body;

//     // Gerekli alanların eksik olup olmadığını kontrol etme
//     if (
//       !formData.name ||
//       !formData.surname ||
//       !formData.university ||
//       !formData.email ||
//       !formData.currentPassword
//     ) {
//       return res.status(400).json({ error: "Missing required fields" });
//     }

//     // Kullanıcının mevcut şifresini veritabanından al
//     const [rows] = await pool.execute(
//       "SELECT password FROM users WHERE id = ?",
//       [decoded.id]
//     );

//     if (rows.length === 0) {
//       return res.status(404).json({ error: "User not found" });
//     }

//     const hashedPassword = rows[0].password; // Veritabanından alınan mevcut şifre

//     // Mevcut şifrenin doğru olup olmadığını kontrol et
//     const isMatch = await bcrypt.compare(
//       formData.currentPassword,
//       hashedPassword
//     );

//     if (!isMatch) {
//       return res.status(400).json({ error: "Current password is incorrect" });
//     }

//     const newHashedPassword = formData.newPassword
//       ? await bcrypt.hash(formData.newPassword, 10) // Yeni şifreyi hash'le
//       : hashedPassword;

//     // Kullanıcının bilgilerini güncelle
//     await pool.execute(
//       "UPDATE users SET name = ?, surname = ?, university = ?, email = ?, password = ? WHERE id = ?",
//       [
//         formData.name,
//         formData.surname,
//         formData.university,
//         formData.email,
//         newHashedPassword,
//         decoded.id,
//       ]
//     );

//     res.status(200).json({ message: "User updated successfully" });
//   } catch (error) {
//     console.error("Error updating user:", error.message);
//     res.status(500).json({ error: "An error occurred during user update" });
//   }
// });

// app.delete("/user", async (req, res) => {
//   const { id } = req.body;

//   try {
//     await pool.execute("DELETE FROM users WHERE id = ?", [id]);
//     res.status(200).json({ message: "User deleted successfully" });
//   } catch (error) {
//     console.error("Error deleting user:", error.message);
//     res.status(500).json({ error: "An error occurred during user deletion" });
//   }
// });

// Excel işlemleri

// Get user info from token

app.get("/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select(
      "name surname email university"
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (error) {
    console.error("Error verifying token:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
});

// Update user info
app.put("/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { name, surname, university, email, currentPassword, newPassword } =
      req.body;

    if (!name || !surname || !university || !email || !currentPassword) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch)
      return res.status(400).json({ error: "Current password is incorrect" });

    user.name = name;
    user.surname = surname;
    user.university = university;
    user.email = email;
    if (newPassword) user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error.message);
    res.status(500).json({ error: "An error occurred during user update" });
  }
});

// Delete user
app.delete("/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await User.findByIdAndDelete(decoded.userId);
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error.message);
    res.status(500).json({ error: "An error occurred during user deletion" });
  }
});

// app.post("/excel-upload", async (req, res) => {
//   const token = req.cookies.token;

//   if (!token) {
//     return res.status(401).json({ error: "Unauthorized" });
//   }

//   try {
//     const decoded = jwt.verify(token, JWT_SECRET);

//     const userId = decoded.id;

//     const { folderId, fileName, arrayData } = req.body;

//     const [result] = await pool.execute(
//       "INSERT INTO excel_files (user_id, folder_id, file_name, file_data) VALUES (?, ?, ?, ?)",
//       [userId, folderId, fileName, arrayData]
//     );

//     res.status(201).json({ id: result.insertId, arrayData });
//   } catch (error) {
//     console.error("Error uploading Excel file:", error.message);
//     res.status(500).json({ error: "An error occurred during Excel upload" });
//   }
// });

// app.post("/excel", async (req, res) => {
//   try {
//     const { fileId } = req.body;

//     const [excel] = await pool.execute(
//       "SELECT id, folder_id, file_name, created_at, file_data FROM excel_files WHERE id = ?",
//       [fileId]
//     );

//     res.status(200).json(excel);
//   } catch (error) {
//     console.error("Error fetching Excel file:", error.message);
//     res
//       .status(500)
//       .json({ error: "An error occurred during fetching Excel file" });
//   }
// });

// app.get("/excels", async (req, res) => {
//   const token = req.cookies.token;

//   if (!token) {
//     return res.status(401).json({ error: "Unauthorized" });
//   }

//   try {
//     const decoded = jwt.verify(token, JWT_SECRET);
//     const [excels] = await pool.execute(
//       "SELECT id, folder_id, file_name , created_at FROM excel_files WHERE user_id = ?",
//       [decoded.id]
//     );

//     res.status(200).json(excels);
//   } catch (error) {
//     console.error("Error fetching Excel file:", error.message);
//     res
//       .status(500)
//       .json({ error: "An error occurred during fetching Excel file" });
//   }
// });

// app.delete("/excel-delete", async (req, res) => {
//   const { fileId } = req.body;
//   try {
//     await pool.execute("DELETE FROM excel_files WHERE id = ?", [fileId]);
//     res.status(200).json({ message: "Excel file deleted successfully" });
//   } catch (error) {
//     console.error("Error deleting Excel file:", error.message);
//     res.status(500).json({ error: "An error occurred during file deletion" });
//   }
// });

// app.put("/excel-update", async (req, res) => {
//   const { id, folder_id, file_name, file_data } = req.body;

//   console.log(id, folder_id, file_name);

//   try {
//     // Veritabanında güncelleme sorgusu
//     const [result] = await pool.execute(
//       "UPDATE excel_files SET folder_id = ?, file_name = ?, file_data = ? WHERE id = ?;",
//       [folder_id, file_name, JSON.stringify(file_data), id]
//     );

//     // Etkilenen satır sayısını kontrol edin
//     if (result.affectedRows > 0) {
//       res.status(200).json({ message: "Excel file updated successfully" });
//     } else {
//       res.status(404).json({ error: "Excel file not found" });
//     }
//   } catch (error) {
//     console.error("Error updating Excel file:", error.message);
//     res
//       .status(500)
//       .json({ error: "An error occurred during updating Excel file" });
//   }
// });

//Klasör işlemleri

// Upload Excel File

app.post("/excel-upload", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { folderId, fileName, arrayData } = req.body;

    const newExcel = new ExcelFile({
      user_id: decoded.userId,
      folder_id: folderId,
      file_name: fileName,
      file_data: arrayData,
    });
    await newExcel.save();

    res.status(201).json({ id: newExcel._id, arrayData });
  } catch (error) {
    console.error("Error uploading Excel file:", error.message);
    res.status(500).json({ error: "An error occurred during Excel upload" });
  }
});

// Get Single Excel File
app.post("/excel", async (req, res) => {
  try {
    const { fileId } = req.body;
    const excel = await ExcelFile.findById(fileId);
    if (!excel) return res.status(404).json({ error: "Excel file not found" });
    res.status(200).json(excel);
  } catch (error) {
    console.error("Error fetching Excel file:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred during fetching Excel file" });
  }
});

// Get All Excel Files for User
app.get("/excels", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const excels = await ExcelFile.find({ user_id: decoded.userId }).select(
      "id folder_id file_name created_at"
    );
    res.status(200).json(excels);
  } catch (error) {
    console.error("Error fetching Excel files:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred during fetching Excel files" });
  }
});

// Delete Excel File
app.delete("/excel-delete", async (req, res) => {
  try {
    const { fileId } = req.body;
    await ExcelFile.findByIdAndDelete(fileId);
    res.status(200).json({ message: "Excel file deleted successfully" });
  } catch (error) {
    console.error("Error deleting Excel file:", error.message);
    res.status(500).json({ error: "An error occurred during file deletion" });
  }
});

// Update Excel File
app.put("/excel-update", async (req, res) => {
  try {
    const { id, folder_id, file_name, file_data } = req.body;
    const updatedExcel = await ExcelFile.findByIdAndUpdate(
      id,
      {
        folder_id,
        file_name,
        file_data,
      },
      { new: true }
    );

    if (!updatedExcel)
      return res.status(404).json({ error: "Excel file not found" });
    res.status(200).json({ message: "Excel file updated successfully" });
  } catch (error) {
    console.error("Error updating Excel file:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred during updating Excel file" });
  }
});

// app.post("/upload-folder", async (req, res) => {
//   try {
//     const { folderName } = req.body;
//     if (!folderName)
//       return res.status(400).json({ message: "Folder name is required" });
//     const [result] = await pool.execute(
//       "INSERT INTO folders (folder_name) VALUES (?)",
//       [folderName]
//     );
//     res.status(201).json({ id: result.insertId, folderName });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.post("/folder", async (req, res) => {
//   try {
//     const { id } = req.body;
//     if (!id)
//       return res.status(400).json({ message: "Folder name is required" });
//     const [folderName] = await pool.execute(
//       "SELECT folder_name FROM folders WHERE id=?",
//       [id]
//     );
//     res.status(201).json({ folderName });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.get("/folders", async (req, res) => {
//   try {
//     const [rows] = await pool.execute("SELECT * FROM folders");
//     res.json(rows);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.put("/update-folder", async (req, res) => {
//   try {
//     const { id, folder_id, file_name, file_data } = req.body;
//     if (!id)
//       return res.status(400).json({ message: "Folder name is required" });
//     const [result] = await pool.execute(
//       "UPDATE folders SET folder_id = ?, file_name =?, file_data =? , WHERE id = ?",
//       [folder_id, file_name, file_data, id]
//     );
//     if (result.affectedRows === 0)
//       return res.status(404).json({ message: "Folder not found" });
//     res.json({ message: "Folder updated successfully" });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// app.delete("/delete-folder", async (req, res) => {
//   try {
//     const { id } = req.body;
//     if (!id)
//       return res.status(400).json({ message: "Folder name is required" });

//     const [result] = await pool.execute("DELETE FROM folders WHERE id = ?", [
//       id,
//     ]);
//     if (result.affectedRows === 0)
//       return res.status(404).json({ message: "Folder not found" });
//     res.json({ message: "Folder deleted successfully" });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// Server başlatma

app.post("/upload-folder", async (req, res) => {
  try {
    const { folderName } = req.body;
    if (!folderName)
      return res.status(400).json({ message: "Folder name is required" });

    const folder = new Folder({ folder_name: folderName });
    await folder.save();

    res.status(201).json({ id: folder._id, folderName });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/folders", async (req, res) => {
  try {
    const folders = await Folder.find();
    res.json(folders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/update-folder", async (req, res) => {
  try {
    const { id, folder_name } = req.body;
    if (!id || !folder_name)
      return res
        .status(400)
        .json({ message: "Folder name and ID are required" });

    const folder = await Folder.findByIdAndUpdate(
      id,
      { folder_name: folder_name },
      { new: true }
    );
    if (!folder) return res.status(404).json({ message: "Folder not found" });

    res.json({ message: "Folder updated successfully", folder });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/delete-folder", async (req, res) => {
  try {
    const { id } = req.body;
    if (!id) return res.status(400).json({ message: "Folder ID is required" });

    const folder = await Folder.findByIdAndDelete(id);
    if (!folder) return res.status(404).json({ message: "Folder not found" });

    res.json({ message: "Folder deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
