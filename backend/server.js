import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

// ================= CONFIGURACIÓN =================
app.use(cors({
  origin: "https://ventadegarage-three.vercel.app",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.options("*", cors());
app.use(express.json());

// ================= CONEXIÓN A MONGO =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Mongo conectado ✅"))
  .catch(err => {
    console.error("Error conectando a Mongo:", err);
    process.exit(1);
  });

// ================= MODELOS =================
const usuarioSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

const esculturaSchema = new mongoose.Schema({
  nombre: String,
  precio: Number,
  material: String,
  usuario: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Usuario"
  }
});

const Usuario = mongoose.model("Usuario", usuarioSchema);
const Escultura = mongoose.model("Escultura", esculturaSchema);

// ================= MIDDLEWARE JWT =================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ msg: "No autorizado" });

  try {
    const token = authHeader.replace("Bearer ", "");
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    return res.status(400).json({ msg: "Token inválido" });
  }
}

// ================= REGISTRO =================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { nombre, email, password } = req.body;

    const existe = await Usuario.findOne({ email });
    if (existe) return res.status(400).json({ msg: "Usuario ya existe" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const nuevo = new Usuario({
      nombre,
      email,
      password: hashedPassword
    });

    await nuevo.save();

    res.json({ mensaje: "Usuario registrado correctamente" });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================= LOGIN =================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const usuario = await Usuario.findOne({ email });
    if (!usuario) return res.status(400).json({ msg: "Usuario no encontrado" });

    const valido = await bcrypt.compare(password, usuario.password);
    if (!valido) return res.status(400).json({ msg: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: usuario._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================= OBTENER ESCULTURAS =================
app.get("/api/esculturas", authMiddleware, async (req, res) => {
  try {
    const esculturas = await Escultura.find({ usuario: req.user.id });
    res.json(esculturas);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================= CREAR ESCULTURA =================
app.post("/api/esculturas", authMiddleware, async (req, res) => {
  try {
    const { nombre, precio, material } = req.body;

    const nueva = new Escultura({
      nombre,
      precio,
      material,
      usuario: req.user.id
    });

    await nueva.save();
    res.json(nueva);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================= ELIMINAR ESCULTURA =================
app.delete("/api/esculturas/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "ID inválido" });
    }

    const escultura = await Escultura.findOne({
      _id: id,
      usuario: req.user.id
    });

    if (!escultura) {
      return res.status(404).json({ message: "No encontrada o no autorizada" });
    }

    await Escultura.deleteOne({ _id: id });

    res.json({ message: "Escultura eliminada correctamente" });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ================= RUTA PRINCIPAL =================
app.get("/", (req, res) => {
  res.json({ status: "API funcionando correctamente 🚀" });
});

// ================= SERVIDOR =================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Servidor corriendo en puerto", PORT);
});