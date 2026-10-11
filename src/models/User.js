// src/models/User.js
// The User collection: describes what we store for each account.

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const ROLES = ["buyer", "seller", "moderator", "admin"];

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },

    // Emails are stored lowercase and must be unique.
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },

    // select: false means this field is NOT returned unless we ask for it.
    passwordHash: { type: String, required: true, select: false },

    role: { type: String, enum: ROLES, default: "buyer" },

    isEmailVerified: { type: Boolean, default: false },

    // Only hashes are stored, never the raw tokens.
    emailVerificationTokenHash: { type: String, select: false },
    emailVerificationExpires: { type: Date, select: false },

    passwordResetTokenHash: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },

    passwordChangedAt: { type: Date, select: false },

    // Used later by the moderator module. Suspended users cannot log in.
    isSuspended: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// Turns a plain password into a safe hash (12 = how much work the hashing does).
userSchema.statics.hashPassword = function hashPassword(plainPassword) {
  return bcrypt.hash(plainPassword, 12);
};

// Checks a typed password against the saved hash.
userSchema.methods.verifyPassword = function verifyPassword(plainPassword) {
  return bcrypt.compare(plainPassword, this.passwordHash);
};

// Even if we forget to hide something, these are removed from API responses.
userSchema.set("toJSON", {
  transform(doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    delete ret.passwordHash;
    delete ret.emailVerificationTokenHash;
    delete ret.emailVerificationExpires;
    delete ret.passwordResetTokenHash;
    delete ret.passwordResetExpires;
    delete ret.passwordChangedAt;
    return ret;
  },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
module.exports.ROLES = ROLES;