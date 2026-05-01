const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  lastLogin: Date,
  lastLogout: Date,
  lastActive: Date,
  isDeleted: { type: Boolean, default: false }
});

// Track activity
userSchema.pre("save", function(next) {
  this.lastActive = new Date();
  next();
});

// Soft delete filter
userSchema.pre(/^find/, function(next) {
  this.find({ isDeleted: false });
  next();
});

module.exports = mongoose.model("User", userSchema);
