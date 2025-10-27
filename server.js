const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");

try {
  require("dotenv").config();
} catch (e) {
}

const app = express();
const port = 5000;

const JWT_SECRET = process.env.JWT_SECRET;
const uri = process.env.MONGO_URI ? String(process.env.MONGO_URI) : undefined;
const frontendURL = process.env.FRONTEND_URL ? String(process.env.FRONTEND_URL) : undefined;

if (!JWT_SECRET || !uri || !frontendURL) {
  console.warn(
    "Warning: Missing environment variables. Make sure you have a .env file in the project root with JWT_SECRET, MONGO_URI and FRONTEND_URL set."
  );
}

// Middleware

app.use(express.json({ limit: "16mb" })); // limiti artır
app.use(express.urlencoded({ extended: true, limit: "16mb" }));
app.use(cookieParser());

const allowedOrigins = [
  "https://testmetrix.vercel.app",
  "http://localhost:3000"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

mongoose
  .connect(uri)
  .then(() => console.log("Connected to MongoDB!"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  surname: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  university: { type: String },
  phone: { type: String },
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
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  folder_name: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});
const Folder = mongoose.model("Folder", folderSchema);

// user authentication
app.get("/user-authentication", (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Yetkisiz erişim" });
  }

  try {
    // Token'ı doğrula
    const decoded = jwt.verify(token, JWT_SECRET);

    res.json({ message: "Token doğrulandı", user: decoded });
  } catch (error) {
    console.error("JWT Hatası:", error);

    if (error.name === "TokenExpiredError") {
      // Eğer token expired ise, çerezi temizle
      res.clearCookie("token", {
        httpOnly: true,
        secure: true,
        sameSite: "None",
      });

      res.cookie("token", "", { expires: new Date(0) }); // Boş çerez set et
      return res
        .status(401)
        .json({ error: "Token süresi doldu, lütfen tekrar giriş yapın!" });
    }

    // Diğer hatalar için
    res.status(401).json({ error: "Geçersiz token" });
  }
});

// Register User
app.post("/register", async (req, res) => {
  try {
    const { name, surname, email, university, role, phone, KVKK, password } =
      req.body;
    //verifyEmail(email);
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      surname,
      email,
      university,
      role,
      phone,
      KVKK,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// user Login
app.post("/login", async (req, res) => {
  try {
    const { email, role, password } = req.body;

    const user = await User.findOne({ email, role });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "6h" }
    );

    // Yeni cookie'yi ekle
    res.cookie("token", token, {
      httpOnly: true,
      secure: true, // Sadece prod ortamında HTTPS zorunlu olsun
      sameSite: "None",
    });

    res.json({ message: "Login successful" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// user logout
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
  });

  res.cookie("token", "", { expires: new Date(0) }); // Boş çerez set et
  res.json({ message: "Çıkış başarılı" });
});

// user forgot password
app.post("/forgot-password", async (req, res) => {
  try {
    const { email, generatedCode } = req.body;

    // Kullanıcıyı e-posta adresine göre bul
    const user = await User.find({ email: email });
    if (!user) return res.status(404).json({ error: "User not found" });

    // SMTP ayarları (Gmail veya başka bir sağlayıcı için)
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "ahmetkurtk2@gmail.com", // Kendi e-posta adresin
        pass: "lxuk beqx hqtl tuqj", // Gmail için uygulama şifresi gerekli olabilir
      },
    });

    // E-posta içeriği
    const mailOptions = {
      from: "ahmetkurtk2@gmail.com",
      to: email,
      subject: "Şifre Sıfırlama Kodu",
      text: `Şifre sıfırlama kodunuz: ${generatedCode}. Bu kod 60 saniye içinde geçerlidir.`,
    };

    // E-posta gönder
    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Reset code sent successfully" });
  } catch (error) {
    console.error("Error sending email:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred while processing the request" });
  }
});

// contact send-mail
app.post("/send-mail", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // Input validation
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Configure email transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "ahmetkurtk2@gmail.com",
        pass: "lxuk beqx hqtl tuqj",
      },
    });

    // Email content
    const mailOptions = {
      from: email,
      to: "ahmetkurtk2@gmail.com", // Where you want to receive contact form messages
      subject: `Contact Form: ${subject}`,
      text: `
        Name: ${name}
        Email: ${email}
        Subject: ${subject}
        
        Message:
        ${message}
      `,
      // Optional HTML version
      html: `
        <h3>New Contact Form Submission</h3>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message}</p>
      `,
    };

    // Send email
    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Message sent successfully" });
  } catch (error) {
    console.error("Error sending contact form email:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred while sending the message" });
  }
});

// Get User
app.get("/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select(
      "name surname email university phone"
    );

    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (error) {
    console.error("Error verifying token:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
});

// Get All Users
app.get("/users", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Token'ı doğrula
    const decoded = jwt.verify(token, JWT_SECRET);

    // Tüm kullanıcıları çek (şifre hariç)
    const users = await User.find({}).select(
      "name surname email university phone role"
    );

    // Kullanıcıları frontend'e gönder
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update User
app.put("/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const {
      name,
      surname,
      university,
      phone,
      email,
      currentPassword,
      newPassword,
    } = req.body;

    if (
      !name ||
      !surname ||
      !university ||
      !phone ||
      !email ||
      !currentPassword
    ) {
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
    user.phone = phone;
    if (newPassword) user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error.message);
    res.status(500).json({ error: "An error occurred during user update" });
  }
});

// Update User Password
app.put("/user-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Kullanıcıyı e-posta adresine göre bul
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Yeni şifreyi hash'le
    user.password = await bcrypt.hash(newPassword, 10);

    // Güncellenmiş kullanıcıyı kaydet
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error.message);
    res.status(500).json({ error: "An error occurred during password update" });
  }
});

// Delete user
app.delete("/user", async (req, res) => {
  const token = req.cookies.token;
  const { password } = req.body;

  if (!token) return res.status(401).json({ error: "Unauthorized" });
  if (!password) return res.status(400).json({ error: "Password is required" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    // Şifreyi kontrol et
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(403).json({ error: "Incorrect password" });
    }

    const userId = new mongoose.Types.ObjectId(decoded.userId);
    const deletedExcels = await ExcelFile.deleteMany({
      user_id: userId,
    });
    const deletedFolders = await Folder.deleteMany({
      user_id: userId,
    });

    // Kullanıcıyı sil
    await User.findByIdAndDelete(decoded.userId);
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error.message);
    res.status(500).json({ error: "An error occurred during user deletion" });
  }
});

// Upload Excel
app.post("/excel-upload", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { folder_id, file_name, file_data } = req.body;

    const newExcel = new ExcelFile({
      user_id: decoded.userId,
      folder_id: folder_id,
      file_name: file_name,
      file_data: file_data,
    });
    await newExcel.save();

    res.status(201).json({ id: newExcel._id, file_data });
  } catch (error) {
    console.error("Error uploading Excel file:", error.message);
    res.status(500).json({ error: "An error occurred during Excel upload" });
  }
});

// Get Single Excel File
app.post("/excel", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
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

// Get All Excel Files
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
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
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
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
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

// Folder işlemleri
app.post("/upload-folder", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { folderName } = req.body;
    if (!folderName)
      return res.status(400).json({ message: "Folder name is required" });

    const folder = new Folder({
      user_id: decoded.userId,
      folder_name: folderName,
    });

    await folder.save();

    res.status(201).json({ id: folder._id, folderName });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get All Folders
app.get("/folders", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const folders = await Folder.find({ user_id: decoded.userId });
    res.json(folders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Folder
app.put("/update-folder", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
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

// Delete Folder
app.delete("/delete-folder", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const { id } = req.body;
    if (!id) return res.status(400).json({ message: "Folder ID is required" });

    const folderObjectId = new mongoose.Types.ObjectId(id);
    const deletedExcels = await ExcelFile.deleteMany({
      folder_id: folderObjectId,
    });

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
