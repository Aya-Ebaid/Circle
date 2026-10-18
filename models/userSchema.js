const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, default: "" },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: { type: String, required: true },
    phone: { type: String, trim: true, default: "" },
    company: { type: String, trim: true, default: "" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);