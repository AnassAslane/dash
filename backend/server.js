const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { Server } = require('socket.io');
const http = require('http');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const JWT_SECRET = 'your_secure_jwt_secret';

// 1. Initialize Socket.io with CORS
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// 2. Middleware
app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));

// 3. Database schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  alertPreferences: {
    maxTemp: { type: Number, default: 30 },
    maxHumidity: { type: Number, default: 70 }
  }
});

const sensorSchema = new mongoose.Schema({
  temperature: Number,
  humidity: Number,
  timestamp: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const User = mongoose.model('User', userSchema);
const SensorData = mongoose.model('SensorData', sensorSchema, 'sensor_data');

// 4. Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) throw new Error('No token provided');
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    if (!req.user) throw new Error('User not found');
    
    next();
  } catch (err) {
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// 5. Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      password: hashedPassword
    });
    await user.save();
    res.status(201).json({ message: 'User created' });
  } catch (error) {
    res.status(400).json({ error: 'Registration failed: ' + error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET);
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username
      },
      alertPreferences: user.alertPreferences
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

app.put('/api/alerts', authenticate, async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $set: { alertPreferences: req.body } },
      { new: true }
    );
    res.json(updatedUser.alertPreferences);
  } catch (error) {
    res.status(400).json({ error: 'Update failed: ' + error.message });
  }
});

// 6. Socket.io handlers
io.on('connection', (socket) => {
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      // Setup MongoDB change stream for real-time updates
      const changeStream = SensorData.watch([{
        $match: {
          'fullDocument.userId': user._id,
          operationType: 'insert'
        }
      }]);

      changeStream.on('change', (change) => {
        const data = change.fullDocument;
        
        // Check for alerts
        if (data.temperature > user.alertPreferences.maxTemp ||
            data.humidity > user.alertPreferences.maxHumidity) {
          socket.emit('alert', {
            message: `Alert! Temp: ${data.temperature}°C, Humidity: ${data.humidity}%`,
            timestamp: new Date().toISOString()
          });
        }
        
        // Send new data to client
        socket.emit('newData', {
          temperature: data.temperature,
          humidity: data.humidity,
          timestamp: data.timestamp
        });
      });

      socket.on('disconnect', () => {
        changeStream.close();
      });

    } catch (err) {
      socket.disconnect();
    }
  });
});

// 7. Database connection
const connectDB = async () => {
  try {
    await mongoose.connect('mongodb://localhost:27017/iot_data', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('MongoDB Connected');
    server.listen(5000, () => {
      console.log('Server running on http://localhost:5000');
    });
  } catch (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
};

connectDB();