const mongoose = require("mongoose");

const customerSchema = new mongoose.Schema(
  {
    firstName: String,
    lastName: String,
    email: String,
    telephone: String,
    age: Number,
    gender: String,
    country: String,
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Customer", customerSchema);