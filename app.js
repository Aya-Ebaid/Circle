const express = require("express");
const dotenv = require("dotenv");
dotenv.config();

const bcrypt = require("bcrypt");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const mongoose = require("mongoose");
const path = require("path");
const moment = require("moment");
const methodOverride = require("method-override");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const crypto = require("crypto");

// Models
const Customer = require("./models/castumarSchema");
const User = require("./models/userSchema");

const app = express();
const port = process.env.PORT || 3001;

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).send("Too many attempts. Please try again in 15 minutes."),
});

//  MongoDB connection
let connectionPromise = null;
function connectDB() {
  if (!connectionPromise) {
    connectionPromise = mongoose.connect(process.env.MONGO_URL).catch((err) => {
      connectionPromise = null;
      throw err;
    });
  }
  return connectionPromise;
}

app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error("DB connection error:", err);
    res.status(500).send("Database connection error");
  }
});

app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));

// moment متاح في كل الـ views
app.locals.moment = moment;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URL,
      collectionName: "sessions",
      touchAfter: 24 * 3600,
    }),
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 7,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

app.use(async (req, res, next) => {
  res.locals.currentUser = null;
  if (req.session.userId) {
    try {
      res.locals.currentUser = await User.findById(req.session.userId).select(
        "-password -avatar.data"
      );
    } catch (err) {
      console.error(err);
    }
  }
  next();
});

function requireLogin(req, res, next) {
  if (req.session.userId && res.locals.currentUser) return next();

  if (req.session.userId) {
    return req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.redirect("/signin");
    });
  }
  res.redirect("/signin");
}

const publicPaths = ["/signin", "/signup", "/demo"];
app.use((req, res, next) => {
  if (publicPaths.includes(req.path)) return next();
  requireLogin(req, res, next);
});

if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) {
  const livereload = require("livereload");
  const connectLivereload = require("connect-livereload");

  const liveReloadServer = livereload.createServer();
  liveReloadServer.watch(path.join(__dirname, "public"));
  app.use(connectLivereload());

  liveReloadServer.server.once("connection", () => {
    setTimeout(() => {
      liveReloadServer.refresh("/");
    }, 100);
  });
}

//  Auth

app.get("/signin", (req, res) => {
  res.render("user/signin", { error: null, email: "" });
});

app.post("/signin", authLimiter, async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  try {
    const user = await User.findOne({ email });
    const isMatch = user && (await bcrypt.compare(req.body.password || "", user.password));

    if (!isMatch) {
      return res.status(401).render("user/signin", {
        error: "Invalid email or password",
        email,
      });
    }

    req.session.userId = user._id.toString();
    res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).render("user/signin", {
      error: "Something went wrong. Please try again.",
      email,
    });
  }
});

app.get("/signup", (req, res) => {
  res.render("user/signup", { error: null, email: "" });
});

app.post("/signup", authLimiter, async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  try {
    if (password.length < 8) {
      return res.status(400).render("user/signup", {
        error: "Password must be at least 8 characters",
        email,
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).render("user/signup", {
        error: "This email is already registered",
        email,
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ email, password: hashedPassword });

    res.redirect("/signin");
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).render("user/signup", {
      error: "Something went wrong. Please try again.",
      email,
    });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).send("Error logging out");
    }
    res.clearCookie("connect.sid");
    res.redirect("/signin");
  });
});

//  Demo account
const demoCustomers = [
  { firstName: "Sara", lastName: "Hassan", email: "sara.hassan@example.com", telephone: "01012345678", age: 29, gender: "Female", country: "Egypt" },
  { firstName: "Omar", lastName: "Khaled", email: "omar.khaled@example.com", telephone: "01123456789", age: 34, gender: "Male", country: "Egypt" },
  { firstName: "Youssef", lastName: "Alami", email: "youssef.alami@example.com", telephone: "0612345678", age: 41, gender: "Male", country: "Morocco" },
  { firstName: "Nour", lastName: "Mahmoud", email: "nour.mahmoud@example.com", telephone: "01234567890", age: 26, gender: "Female", country: "Egypt" },
  { firstName: "Salma", lastName: "Benali", email: "salma.benali@example.com", telephone: "0698765432", age: 31, gender: "Female", country: "Morocco" },
  { firstName: "Karim", lastName: "Adel", email: "karim.adel@example.com", telephone: "01098765432", age: 38, gender: "Male", country: "Egypt" },
  { firstName: "Layla", lastName: "Idrissi", email: "layla.idrissi@example.com", telephone: "0655443322", age: 24, gender: "Female", country: "Morocco" },
  { firstName: "Hassan", lastName: "Fathy", email: "hassan.fathy@example.com", telephone: "01511223344", age: 45, gender: "Male", country: "Egypt" },
];

app.post("/demo", authLimiter, async (req, res) => {
  try {
    const expireAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // يتمسح بعد 24 ساعة
    const id = crypto.randomBytes(6).toString("hex");

    const user = await User.create({
      name: "Demo Visitor",
      email: `demo-${id}@circle-demo.local`,
      password: await bcrypt.hash(crypto.randomBytes(24).toString("hex"), 10),
      expireAt,
    });

    await Customer.insertMany(
      demoCustomers.map((c) => ({ ...c, user: user._id, expireAt }))
    );

    req.session.userId = user._id.toString();
    res.redirect("/");
  } catch (err) {
    console.error("Demo error:", err);
    res.status(500).render("user/signin", {
      error: "Could not start the demo. Please try again.",
      email: "",
    });
  }
});

// Profile 
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    const ok = ["image/jpeg", "image/png", "image/webp"].includes(file.mimetype);
    cb(ok ? null : new Error("Only JPG, PNG or WEBP images are allowed"), ok);
  },
});

app.get("/profile", async (req, res) => {
  try {
    const customersCount = await Customer.countDocuments({ user: req.session.userId });
    res.render("user/profile", { customersCount });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading profile");
  }
});

app.put("/profile", async (req, res) => {
  try {
    const name = (req.body.name || "").trim();
    const phone = (req.body.phone || "").trim();
    const company = (req.body.company || "").trim();
    await User.updateOne({ _id: req.session.userId }, { $set: { name, phone, company } });
    res.redirect("/profile");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error updating profile");
  }
});

app.get("/profile/avatar", async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select("avatar");
    if (!user || !user.avatar || !user.avatar.data) {
      return res.status(404).end();
    }
    res.set("Content-Type", user.avatar.contentType);
    res.set("Cache-Control", "private, max-age=86400");
    res.send(user.avatar.data);
  } catch (err) {
    console.error(err);
    res.status(500).end();
  }
});

app.post("/profile/avatar", (req, res) => {
  upload.single("avatar")(req, res, async (err) => {
    if (err) {
      const msg =
        err.code === "LIMIT_FILE_SIZE" ? "Image must be smaller than 2MB" : err.message;
      return res.status(400).send(`${msg}. <a href="/profile">Back</a>`);
    }
    try {
      if (!req.file) return res.redirect("/profile");
      await User.updateOne(
        { _id: req.session.userId },
        { avatar: { data: req.file.buffer, contentType: req.file.mimetype } }
      );
      res.redirect("/profile");
    } catch (e) {
      console.error(e);
      res.status(500).send("Error uploading photo");
    }
  });
});

app.delete("/profile/avatar", async (req, res) => {
  try {
    await User.updateOne({ _id: req.session.userId }, { $unset: { avatar: "" } });
    res.redirect("/profile");
  } catch (e) {
    console.error(e);
    res.status(500).send("Error removing photo");
  }
});

//  Customers 

app.get("/", (req, res) => {
  Customer.find({ user: req.session.userId })
    .then((result) => res.render("index", { arr: result }))
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error fetching customers");
    });
});

app.get("/user/add.html", (req, res) => {
  res.render("user/add");
});

app.get("/edit/:id", (req, res) => {
  Customer.findOne({ _id: req.params.id, user: req.session.userId })
    .then((result) => {
      if (!result) return res.status(404).send("Customer not found");

      res.render("user/edit", { arr: result }, (err, html) => {
        if (err) {
          console.error("EDIT RENDER ERROR:", err.message);
          return res.status(500).send("<pre>" + err.message + "</pre>");
        }
        res.send(html);
      });
    })
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error fetching customer");
    });
});

app.get("/user/:id", (req, res) => {
  Customer.findOne({ _id: req.params.id, user: req.session.userId })
    .then((result) => {
      if (!result) return res.status(404).send("Customer not found");
      res.render("user/view", { arr: result });
    })
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error fetching customer");
    });
});

app.post("/user/add.html", (req, res) => {
  const { firstName, lastName, email, telephone, age, gender, country } = req.body;
  Customer.create({
    firstName,
    lastName,
    email,
    telephone,
    age,
    gender,
    country,
    user: req.session.userId,
  })
    .then(() => res.redirect("/"))
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error adding customer");
    });
});

app.put("/edit/:id", (req, res) => {
  const { firstName, lastName, email, telephone, age, gender, country } = req.body;
  Customer.updateOne(
    { _id: req.params.id, user: req.session.userId },
    { firstName, lastName, email, telephone, age, gender, country }
  )
    .then(() => res.redirect("/"))
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error updating customer");
    });
});

app.delete("/delete/:id", (req, res) => {
  Customer.deleteOne({ _id: req.params.id, user: req.session.userId })
    .then(() => res.redirect("/"))
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error deleting customer");
    });
});

app.post("/search", (req, res) => {
  const term = (req.body.search || "").trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  Customer.find({
    user: req.session.userId,
    firstName: { $regex: term, $options: "i" },
  })
    .then((result) => res.render("user/search", { arr: result }))
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error searching customers");
    });
});

// Server 
if (!process.env.VERCEL) {
  connectDB()
    .then(() => {
      console.log("Connected to MongoDB");
      app.listen(port, () => {
        console.log(`Server running on port ${port}`);
      });
    })
    .catch((err) => {
      console.error("Error connecting to MongoDB:", err);
    });
}

module.exports = app;
