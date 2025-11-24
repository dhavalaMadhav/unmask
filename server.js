require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const cors = require('cors'); 
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const connectDB = require('./db/connection');
const { Message, User } = require('./db/schemas');
const auth = require('./middleware/auth');

// --------------------------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e8,
  pingTimeout: 60000
});

// Connect to MongoDB
connectDB();

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'views'))); // ⬅ ADD THIS

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Utility: Generate anonymous name
function generateAnonName() {
  const adjectives = ['Silent', 'Brave', 'Quiet', 'Gentle', 'Strong', 'Peaceful', 'Calm', 'Bold', 'Free', 'Kind', 'Wise', 'Swift', 'Bright', 'Dark', 'Light', 'Mystery', 'Shadow', 'Serene', 'Noble', 'Fierce'];
  const animals = ['Wolf', 'Eagle', 'Tiger', 'Bear', 'Fox', 'Owl', 'Hawk', 'Lion', 'Deer', 'Raven', 'Phoenix', 'Dragon', 'Falcon', 'Panther', 'Leopard', 'Dove', 'Swan', 'Butterfly', 'Dolphin', 'Whale'];
  if (Math.random() > 0.5) {
    const randomAdjective = adjectives[Math.floor(Math.random() * adjectives.length)];
    const randomAnimal = animals[Math.floor(Math.random() * animals.length)];
    const randomNumber = Math.floor(Math.random() * 9999) + 1;
    return `${randomAdjective}${randomAnimal}${randomNumber}`;
  } else {
    const randomNumber = Math.floor(Math.random() * 9999) + 1000;
    return `Anon#${randomNumber}`;
  }
}

// -------------------
// VIEWS
// -------------------
app.get('/', (req, res) => res.render('index'));
app.get('/register', (req, res) => res.render('register'));
app.get('/login', (req, res) => res.render('login'));
app.get('/dashboard', (req, res) => res.render('dashboard'));
app.get('/chat', (req, res) => res.render('chat'));
app.get('/settings', (req, res) => res.render('settings'));
// ------------------------
// AUTH API
// ------------------------

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 10);

    let anonName;
    let isUnique = false;
    while (!isUnique) {
      anonName = generateAnonName();
      const existing = await User.findOne({ anonName });
      if (!existing) isUnique = true;
    }
    const user = new User({ email, passwordHash, anonName });
    await user.save();

    res.status(201).json({
      message: 'Registration successful',
      anonName: user.anonName
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });
    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ error: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch)
      return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      anonName: user.anonName
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user profile
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    res.json({
      userId: req.user._id,
      email: req.user.email,
      anonName: req.user.anonName,
      profileImage: req.user.profileImage || null,
      createdAt: req.user.createdAt
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Update profile image
app.post('/api/auth/profile-image', auth, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image || !image.startsWith('data:image/'))
      return res.status(400).json({ message: 'Invalid image format' });

    // Check size (base64 is ~33% larger than file)
    const sizeInBytes = (image.length * 3) / 4;
    if (sizeInBytes > 5 * 1024 * 1024)
      return res.status(400).json({ message: 'Image size must be less than 5MB' });

    req.user.profileImage = image;
    await req.user.save();
    res.json({ message: 'Profile image updated', profileImage: image });
  } catch (error) {
    res.status(500).json({ message: 'Failed to upload image' });
  }
});

// Delete profile image
app.delete('/api/auth/profile-image', auth, async (req, res) => {
  try {
    req.user.profileImage = null;
    await req.user.save();
    res.json({ message: 'Profile image removed' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to remove image' });
  }
});

// Update custom username (anonName)
app.put('/api/auth/username', auth, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ message: 'Username is required' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ message: 'Invalid username format' });

    // Check uniqueness (not current user)
    const exists = await User.findOne({ anonName: username });
    if (exists && exists._id.toString() !== req.user._id.toString())
      return res.status(400).json({ message: 'Username already taken' });

    req.user.anonName = username;
    await req.user.save();
    res.json({ message: 'Username updated', anonName: username });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update username' });
  }
});

// -------------------------
// CHAT API
// -------------------------
app.get('/api/chat/rooms', auth, (req, res) => {
  const rooms = [
    { id: 'anxiety-support', name: 'Anxiety Support', description: 'Share and overcome anxiety together' },
    { id: 'career-doubts', name: 'Career Doubts', description: 'Navigate your career uncertainties' },
    { id: 'relationship-issues', name: 'Relationship Issues', description: 'Discuss relationship challenges' },
    { id: 'self-esteem-help', name: 'Self-esteem Help', description: 'Build confidence and self-worth' },
    { id: 'open-lounge', name: 'Open Lounge', description: 'Talk about anything on your mind' }
  ];
  res.json({ rooms });
});

app.get('/api/chat/messages/:room', auth, async (req, res) => {
  try {
    const { room } = req.params;
    const messages = await Message.find({ room })
      .sort({ timestamp: -1 })
      .limit(50)
      .lean();
    messages.reverse();
    res.json({ messages });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// -----------------------------
// SOCKET.IO
// -----------------------------
const roomUsers = {};

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error'));
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return next(new Error('User not found'));

    socket.userId = user._id.toString();
    socket.anonName = user.anonName;
    socket.profileImage = user.profileImage || null;  // <-- Inject profileImage here

    next();
  } catch (error) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
// In io.on('connection') joinRoom:
socket.on('joinRoom', async ({ room }) => {
  socket.join(room);

  if (!roomUsers[room]) {
    roomUsers[room] = {};
  }
  roomUsers[room][socket.id] = {
    userId: socket.userId,
    anonName: socket.anonName,
    profileImage: socket.profileImage  // <-- Track profileImage here
  };

  socket.to(room).emit('userJoined', {
    anonName: socket.anonName,
    message: `${socket.anonName} joined the room`
  });

// When emitting updated onlineUsers on disconnect or leaveRoom:
const onlineUsers = Object.values(roomUsers[room]).map(u => ({
  anonName: u.anonName,
  profileImage: u.profileImage  // <-- Include on online users update
}));
io.to(room).emit('onlineUsers', onlineUsers);

});

  const messageTimestamps = [];


  // ---- Message Editing -------
  socket.on('editMessage', async ({ messageId, newText, room }) => {
    try {
      const message = await Message.findById(messageId);
      if (!message) return socket.emit('error', { message: 'Message not found' });
      if (message.senderUserId.toString() !== socket.userId)
        return socket.emit('error', { message: 'Unauthorized to edit this message' });

      const now = Date.now();
      const messageTime = new Date(message.timestamp).getTime();
      const timeDiff = now - messageTime;
      const tenMinutes = 10 * 60 * 1000;
      if (timeDiff > tenMinutes)
        return socket.emit('error', { message: 'Edit time limit exceeded (10 minutes)' });
      if (message.messageType !== 'text')
        return socket.emit('error', { message: 'Cannot edit media messages' });

      message.message = newText.trim().substring(0, 500);
      message.isEdited = true;
      message.editedAt = new Date();
      await message.save();
      io.to(room).emit('messageEdited', {
        messageId,
        newText: message.message,
        isEdited: true,
        editedAt: message.editedAt
      });
    } catch (error) {
      socket.emit('error', { message: 'Failed to edit message' });
    }
  });

  // ---- Message Deletion -----
  socket.on('deleteMessages', async ({ messageIds, room }) => {
    try {
      const messages = await Message.find({
        _id: { $in: messageIds },
        senderUserId: socket.userId
      });
      if (messages.length !== messageIds.length)
        return socket.emit('error', { message: 'Cannot delete messages from other users' });

      await Message.deleteMany({
        _id: { $in: messageIds },
        senderUserId: socket.userId
      });
      io.to(room).emit('messagesDeleted', { messageIds });
    } catch (error) {
      socket.emit('error', { message: 'Failed to delete messages' });
    }
  });

  // ---- Message Creation -----
socket.on('message', async ({ room, text, type = 'text', fileName, fileSize, iv }) => {
  try {
    const now = Date.now();
    messageTimestamps.push(now);
    const recentMessages = messageTimestamps.filter(t => now - t < 10000);
    if (recentMessages.length > 10) {
      socket.emit('error', { message: 'Slow down! Too many messages.' });
      return;
    }

    if (!text) return; // text = ciphertext (or plaintext if not encrypted)

    const message = new Message({
      room,
      senderAnonName: socket.anonName,
      senderUserId: socket.userId,
      messageType: type,
      message: text,          // ciphertext base64
      iv: iv || null,         // store IV if provided
      fileName: fileName || null,
      fileSize: fileSize || null
    });

    await message.save();

    io.to(room).emit('message', {
      messageId: message._id.toString(),
      anonName: socket.anonName,
      profileImage: socket.profileImage,
      userId: socket.userId,
      message: text,          // ciphertext
      iv: iv || null,         // send IV to clients
      messageType: type,
      fileName: fileName,
      fileSize: fileSize,
      isEdited: false,
      timestamp: message.timestamp
    });

    socket.to(room).emit('notification', {
      message: `${socket.anonName} sent a message`,
      room: room
    });
  } catch (error) {
    console.error(error);
    socket.emit('error', { message: 'Failed to send message' });
  }
});

  socket.on('typing', ({ room }) => {
    socket.to(room).emit('typing', { anonName: socket.anonName });
  });

  socket.on('stopTyping', ({ room }) => {
    socket.to(room).emit('stopTyping', { anonName: socket.anonName });
  });

  socket.on('leaveRoom', ({ room }) => {
    socket.leave(room);
    if (roomUsers[room]) {
      delete roomUsers[room][socket.id];
      const onlineUsers = Object.values(roomUsers[room]).map(u => u.anonName);
      io.to(room).emit('onlineUsers', onlineUsers);
      socket.to(room).emit('userLeft', {
        anonName: socket.anonName,
        message: `${socket.anonName} left the room`
      });
    }
  });

  socket.on('disconnect', () => {
    for (const room in roomUsers) {
      if (roomUsers[room][socket.id]) {
        delete roomUsers[room][socket.id];
        const onlineUsers = Object.values(roomUsers[room]).map(u => u.anonName);
        io.to(room).emit('onlineUsers', onlineUsers);
        io.to(room).emit('userLeft', {
          anonName: socket.anonName,
          message: `${socket.anonName} left the room`
        });
      }
    }
  });
});

// ---------------------------
// START SERVER
// ---------------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
