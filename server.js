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

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Connect to MongoDB
connectDB();

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// ============================================
// UTILITY FUNCTIONS (No separate utils folder)
// ============================================
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

// ============================================
// VIEW ROUTES
// ============================================
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/dashboard', (req, res) => {
  res.render('dashboard');
});

app.get('/chat', (req, res) => {
  res.render('chat');
});

// ============================================
// AUTH API ROUTES
// ============================================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    let anonName;
    let isUnique = false;
    while (!isUnique) {
      anonName = generateAnonName();
      const existing = await User.findOne({ anonName });
      if (!existing) isUnique = true;
    }

    const user = new User({
      email,
      passwordHash,
      anonName
    });

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

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    res.json({
      userId: req.user._id,
      email: req.user.email,
      anonName: req.user.anonName,
      createdAt: req.user.createdAt
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// ============================================
// CHAT API ROUTES
// ============================================

// Get all rooms
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

// Get chat history
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
    console.error('Fetch messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// ============================================
// SOCKET.IO REAL-TIME CHAT
// ============================================
const roomUsers = {};

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    
    if (!token) {
      return next(new Error('Authentication error'));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return next(new Error('User not found'));
    }

    socket.userId = user._id.toString();
    socket.anonName = user.anonName;
    next();
  } catch (error) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log(`✅ User connected: ${socket.anonName}`);

  socket.on('joinRoom', async ({ room }) => {
    socket.join(room);
    
    if (!roomUsers[room]) {
      roomUsers[room] = {};
    }
    roomUsers[room][socket.id] = {
      userId: socket.userId,
      anonName: socket.anonName
    };

    socket.to(room).emit('userJoined', {
      anonName: socket.anonName,
      message: `${socket.anonName} joined the room`
    });

    const onlineUsers = Object.values(roomUsers[room]).map(u => u.anonName);
    io.to(room).emit('onlineUsers', onlineUsers);
  });

  const messageTimestamps = [];
  socket.on('message', async ({ room, text }) => {
    try {
      const now = Date.now();
      messageTimestamps.push(now);
      const recentMessages = messageTimestamps.filter(t => now - t < 10000);
      
      if (recentMessages.length > 5) {
        socket.emit('error', { message: 'Slow down! Too many messages.' });
        return;
      }

      const sanitizedText = text.trim().substring(0, 500);
      
      if (!sanitizedText) return;

      const message = new Message({
        room,
        senderAnonName: socket.anonName,
        senderUserId: socket.userId,
        message: sanitizedText
      });

      await message.save();

      io.to(room).emit('message', {
        anonName: socket.anonName,
        message: sanitizedText,
        timestamp: message.timestamp
      });

    } catch (error) {
      console.error('Message error:', error);
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
    console.log(`❌ User disconnected: ${socket.anonName}`);
    
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

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

