const mongoose = require('mongoose');
const validator = require('validator');

// User Schema
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
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Message Schema
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
  message: {
    type: String,
    required: true,
    maxlength: 500
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

messageSchema.index({ room: 1, timestamp: -1 });

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

module.exports = { User, Message };
