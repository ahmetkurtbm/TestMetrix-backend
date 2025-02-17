const express = require("express");
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
app.use(cors({ origin: true, credentials: true }));

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
    res.json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User
app.get("/user", async (req, res) => {
  const token = req.cookies.token;
  // if (!token) return res.status(401).json({ error: "Unauthorized" });

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

// Update User
app.put("/user", async (req, res) => {
  const token = req.cookies.token;
  // if (!token) return res.status(401).json({ error: "Unauthorized" });

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
  const { password } = req.body;

  // if (!token) return res.status(401).json({ error: "Unauthorized" });
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
  // if (!token) return res.status(401).json({ error: "Unauthorized" });

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
  // const token = req.cookies.token;
  // if (!token) return res.status(401).json({ error: "Unauthorized" });

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

// Folder işlemleri
app.post("/upload-folder", async (req, res) => {
  const token = req.cookies.token;
  // if (!token) return res.status(401).json({ error: "Unauthorized" });

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
  try {
    const folders = await Folder.find();
    res.json(folders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Folder
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

// Delete Folder
app.delete("/delete-folder", async (req, res) => {
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
