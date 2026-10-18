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

app.set("view engine", "ejs");
app.use(express.static("public"));
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
    }),
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 7,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

// بيانات اليوزر متاحة في كل الصفحات
app.use(async (req, res, next) => {
  res.locals.currentUser = null;
  if (req.session.userId) {
    try {
      res.locals.currentUser = await User.findById(req.session.userId).select("-password");
    } catch (err) {
      console.error(err);
    }
  }
  next();
});

// الحماية
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/signin");
  }
  next();
}

const publicPaths = ["/signin", "/signup"];

app.use((req, res, next) => {
  if (publicPaths.includes(req.path)) return next();
  requireLogin(req, res, next);
});

// Livereload (development only)
if (process.env.NODE_ENV !== "production") {
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

// ================= Auth =================

app.get("/signin", (req, res) => {
  res.render("user/signin", { error: null, email: "" });
});

app.post("/signin", authLimiter, async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  try {
    const user = await User.findOne({ email });
    const isMatch = user && (await bcrypt.compare(req.body.password, user.password));

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

// ================= Profile & Settings =================

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
    const { name, phone, company } = req.body;
    await User.updateOne({ _id: req.session.userId }, { name, phone, company });
    res.redirect("/profile");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error updating profile");
  }
});

app.get("/settings", (req, res) => {
  res.render("user/settings");
});

// ================= Customers =================

// الصفحة الرئيسية
app.get("/", (req, res) => {
  Customer.find({ user: req.session.userId })
    .then((result) => res.render("index", { arr: result }))
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error fetching customers");
    });
});

// صفحة إضافة عميل
app.get("/user/add.html", (req, res) => {
  res.render("user/add");
});

// صفحة التعديل
app.get("/edit/:id", (req, res) => {
  Customer.findOne({ _id: req.params.id, user: req.session.userId })
    .then((result) => {
      if (!result) return res.status(404).send("Customer not found");
      res.render("user/edit", { arr: result });
    })
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error fetching customer");
    });
});

// عرض عميل (لازم يفضل بعد /user/add.html)
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

// إضافة عميل
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

// تعديل عميل
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

// حذف عميل
app.delete("/delete/:id", (req, res) => {
  Customer.deleteOne({ _id: req.params.id, user: req.session.userId })
    .then(() => res.redirect("/"))
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error deleting customer");
    });
});

// بحث
app.post("/search", (req, res) => {
  const term = req.body.search.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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

// ================= MongoDB + Server =================

mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("Connected to MongoDB");
    app.listen(port, () => {
      console.log(`Server running at ${process.env.NODE_ENV || "development"} mode on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
  });