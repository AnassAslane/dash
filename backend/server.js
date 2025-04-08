const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { Server } = require('socket.io');
const http = require('http');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const JWT_SECRET = 'your_secure_jwt_secret';

const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later'
});

// Database schemas
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

const deviceSchema = new mongoose.Schema({
  name: String,
  type: String,
  location: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  lastActive: Date
});

const User = mongoose.model('User', userSchema);
const SensorData = mongoose.model('SensorData', sensorSchema, 'sensor_data');
const Device = mongoose.model('Device', deviceSchema);

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

app.post('/api/auth/register', authLimiter, async (req, res) => {
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

app.post('/api/auth/login', authLimiter, async (req, res) => {
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

app.get('/api/data/historical', authenticate, async (req, res) => {
  try {
    const range = req.query.range;
    const now = new Date();
    let startDate = new Date(now);

    switch(range) {
      case '1h': startDate.setHours(now.getHours() - 1); break;
      case '24h': startDate.setDate(now.getDate() - 1); break;
      case '7d': startDate.setDate(now.getDate() - 7); break;
      default: startDate = new Date(0);
    }

    const data = await SensorData.find({
      userId: req.user._id,
      timestamp: { $gte: startDate }
    }).sort({ timestamp: -1 });

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch historical data' });
  }
});

app.post('/api/devices', authenticate, async (req, res) => {
  try {
    const device = new Device({
      ...req.body,
      userId: req.user._id,
      lastActive: new Date()
    });
    await device.save();
    res.status(201).json(device);
  } catch (error) {
    res.status(400).json({ error: 'Device registration failed' });
  }
});

io.on('connection', (socket) => {
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      const sensorChangeStream = SensorData.watch([{ 
        $match: { 
          'fullDocument.userId': user._id,
          'operationType': 'insert'
        } 
      }]);

      const deviceChangeStream = Device.watch([{
        $match: {
          'fullDocument.userId': user._id,
          'operationType': { $in: ['insert', 'update'] }
        }
      }]);

      sensorChangeStream.on('change', (change) => {
        const data = change.fullDocument;
        if (data.temperature > user.alertPreferences.maxTemp ||
            data.humidity > user.alertPreferences.maxHumidity) {
          socket.emit('alert', {
            message: `Alert! Temp: ${data.temperature}°C, Humidity: ${data.humidity}%`,
            timestamp: new Date().toISOString()
          });
        }
        socket.emit('newData', data);
      });

      deviceChangeStream.on('change', (change) => {
        socket.emit('deviceUpdate', change.fullDocument);
      });

      socket.on('disconnect', () => {
        sensorChangeStream.close();
        deviceChangeStream.close();
      });

    } catch (err) {
      socket.disconnect();
    }
  });
});

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