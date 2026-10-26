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
    avatar: {
      data: Buffer,
      contentType: String,
    },
    expireAt: { type: Date },
  },
  { timestamps: true }
);
userSchema.index({ expireAt: 1 }, { expireAfterSeconds: 0 });
module.exports = mongoose.model("User", userSchema);