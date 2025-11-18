const mongoose = require('mongoose');
const validator = require('validator');

// User Schema with Email Authentication + Profile Image
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  passwordHash: {
    type: String,
    required: [true, 'Password is required'],
    minlength: 6
  },
  anonName: {
    type: String,
    required: true,
    unique: true
  },
  profileImage: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Add indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ anonName: 1 });

// Updated Message Schema with edit tracking
const messageSchema = new mongoose.Schema({
  room: {
    type: String,
    required: true,
    enum: ['anxiety-support', 'career-doubts', 'relationship-issues', 'self-esteem-help', 'open-lounge']
  },
  senderAnonName: {
    type: String,
    required: true
  },
  senderUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  messageType: {
    type: String,
    enum: ['text', 'image', 'file', 'audio'],
    default: 'text'
  },
  message: {
    type: String,
    required: true,
    maxlength: 5000000
  },
  fileName: {
    type: String
  },
  fileSize: {
    type: Number
  },
  isEdited: {
    type: Boolean,
    default: false
  },
  editedAt: {
    type: Date
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

messageSchema.index({ room: 1, timestamp: -1 });
messageSchema.index({ senderUserId: 1 });

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

module.exports = { User, Message };
