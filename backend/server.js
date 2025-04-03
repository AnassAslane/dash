const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);

// Configure CORS
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Connect to MongoDB with error handling
const connectDB = async () => {
  try {
    await mongoose.connect('mongodb://localhost:27017/iot_data', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('MongoDB Connected');
  } catch (err) {
    console.error('MongoDB Connection Error:', err);
    process.exit(1);
  }
};

// Define schema
const sensorSchema = new mongoose.Schema({
  temperature: Number,
  humidity: Number,
  timestamp: { type: Date, default: Date.now }
});

const SensorData = mongoose.model('SensorData', sensorSchema, 'sensor_data');

// API endpoint with error handling
app.get('/api/data', async (req, res) => {
  try {
    const data = await SensorData.find().sort({ timestamp: -1 }).limit(50);
    res.json(data);
  } catch (error) {
    console.error('API Error:', error);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});

// WebSocket with error handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  try {
    const changeStream = SensorData.watch();
    
    changeStream.on('change', (change) => {
      if (change.operationType === 'insert') {
        io.emit('newData', change.fullDocument);
      }
    });

    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
      changeStream.close();
    });

  } catch (err) {
    console.error('Change Stream Error:', err);
    socket.disconnect();
  }
});

// Start server
const startServer = async () => {
  await connectDB();
  server.listen(5000, () => {
    console.log('Backend running on http://localhost:5000');
  });
};

startServer();
