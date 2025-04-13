const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { Server } = require('socket.io');
const http = require('http');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

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
const notificationSchema = new mongoose.Schema({
  message: String,
  timestamp: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
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

deviceSchema.virtual('status').get(function() {
  const inactiveTime = Date.now() - this.lastActive.getTime();
  return inactiveTime < 300000 ? 'online' : 'offline';
});

const User = mongoose.model('User', userSchema);
const SensorData = mongoose.model('SensorData', sensorSchema, 'sensor_data');
const Device = mongoose.model('Device', deviceSchema);
const Notification = mongoose.model('Notification', notificationSchema);

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

const validateDevice = [
  body('name').trim().escape().notEmpty(),
  body('location').trim().escape().notEmpty(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

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
        username: user.username,
        role: user.role
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
    const getStartDate = (range) => {
      const now = new Date();
      const startDate = new Date(now);
      
      switch(range) {
        case '1h': startDate.setHours(now.getHours() - 1); break;
        case '24h': startDate.setDate(now.getDate() - 1); break;
        case '7d': startDate.setDate(now.getDate() - 7); break;
        default: startDate.setDate(now.getDate() - 1);
      }
      return startDate;
    };

    const data = await SensorData.find({
      userId: req.user._id,
      timestamp: { $gte: getStartDate(req.query.range) }
    }).sort({ timestamp: -1 });

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch historical data' });
  }
});

app.get('/api/devices', authenticate, async (req, res) => {
  try {
    const query = req.user.role === 'admin' ? {} : { userId: req.user._id };
    const devices = await Device.find(query);
    res.json(devices);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
});

app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user._id })
      .sort({ timestamp: -1 })
      .limit(50);
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.get('/api/data/export', authenticate, async (req, res) => {
  try {
    const getStartDate = (range) => {
      const now = new Date();
      const startDate = new Date(now);
      
      switch(range) {
        case '1h': startDate.setHours(now.getHours() - 1); break;
        case '24h': startDate.setDate(now.getDate() - 1); break;
        case '7d': startDate.setDate(now.getDate() - 7); break;
        default: startDate.setDate(now.getDate() - 1);
      }
      return startDate;
    };

    const data = await SensorData.find({
      userId: req.user._id,
      timestamp: { $gte: getStartDate(req.query.range) }
    }).sort({ timestamp: -1 });

    let csv = 'Timestamp,Temperature,Humidity\n';
    data.forEach(d => {
      csv += `${d.timestamp.toISOString()},${d.temperature},${d.humidity}\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=sensor-data.csv');
    res.send(csv);
  } catch (error) {
    res.status(500).json({ error: 'Export failed' });
  }
});

app.post('/api/devices', authenticate, validateDevice, async (req, res) => {
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
app.post('/api/data', authenticate, async (req, res) => {
  try {
    const newData = new SensorData({
      temperature: req.body.temperature,
      humidity: req.body.humidity,
      userId: req.user._id
    });
    
    await newData.save();
    res.status(201).json(newData);
  } catch (error) {
    res.status(400).json({ error: 'Failed to save sensor data' });
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

      sensorChangeStream.on('change', async (change) => {
        const data = change.fullDocument;
        if (data.temperature > user.alertPreferences.maxTemp ||
            data.humidity > user.alertPreferences.maxHumidity) {
          const notification = new Notification({
            message: `Alert! Temp: ${data.temperature}°C, Humidity: ${data.humidity}%`,
            userId: user._id
          });
          await notification.save();
          
          socket.emit('alert', {
            message: notification.message,
            timestamp: notification.timestamp
          });
        }
        socket.emit('newData', data);
      });

      deviceChangeStream.on('change', async (change) => {
        if (change.operationType === 'update') {
          await Device.findByIdAndUpdate(
            change.documentKey._id,
            { lastActive: new Date() }
          );
        }
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
    
    await Device.createIndexes({ userId: 1 });
    await Notification.createIndexes({ userId: 1, timestamp: -1 });
    
    server.listen(5000, () => {
      console.log('Server running on http://localhost:5000');
    });
  } catch (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
};

connectDB();