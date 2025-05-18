'use strict';


require('dotenv').config();
const express            = require('express');
const mongoose           = require('mongoose');
const cors               = require('cors');
const helmet             = require('helmet');
const mongoSanitize      = require('express-mongo-sanitize');
const xssClean           = require('xss-clean');
const morgan             = require('morgan');
require('express-async-errors');
const { Server }         = require('socket.io');
const http               = require('http');
const bcrypt             = require('bcrypt');
const jwt                = require('jsonwebtoken');
const rateLimit          = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const {
  PORT           = 5000,
  MONGO_URI,
  JWT_SECRET,
  JWT_EXPIRES_IN = '1h',
  CORS_ORIGIN    = 'http://localhost:3000',
  SALT_ROUNDS    = 12
} = process.env;

if (!MONGO_URI || !JWT_SECRET) {
  throw new Error('MONGO_URI and JWT_SECRET must be defined in your environment');
}

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: CORS_ORIGIN, methods: ['GET', 'POST', 'DELETE'], credentials: true }
});

app.set('trust proxy', 1);
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(mongoSanitize());
app.use(xssClean());
app.use(morgan('dev'));

// Rate‑limit auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});

const notificationSchema = new mongoose.Schema({
  message:   { type: String, required: true, trim: true },
  timestamp: { type: Date, default: Date.now },
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  read:      { type: Boolean, default: false }
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true, trim: true },
  password: { type: String, required: true, minlength: 8, select: false },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  alertPreferences: {
    maxTemp:     { type: Number, default: 30 },
    maxHumidity: { type: Number, default: 70 }
  }
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, Number(SALT_ROUNDS));
  next();
});

userSchema.methods.correctPassword = async function (candidate, actual) {
  return bcrypt.compare(candidate, actual);
};

const sensorSchema = new mongoose.Schema({
  temperature: { type: Number, required: true },
  humidity:    { type: Number, required: true },
  timestamp:   { type: Date, default: Date.now },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true }
});

const deviceSchema = new mongoose.Schema({
  name:       { type: String, required: true },
  type:       { type: String },
  location:   { type: String },
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  lastActive: { type: Date, default: Date.now }
});

deviceSchema.virtual('status').get(function () {
  return Date.now() - this.lastActive.getTime() < 300_000 ? 'online' : 'offline';
});

deviceSchema.set('toJSON', { virtuals: true });

const User         = mongoose.model('User', userSchema);
const SensorData   = mongoose.model('SensorData', sensorSchema);
const Device       = mongoose.model('Device', deviceSchema);
const Notification = mongoose.model('Notification', notificationSchema);


const signToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

const authenticate = async (req, _res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return next({ statusCode: 401, message: 'Missing token' });

  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const user    = await User.findById(decoded.id);
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch {
    next({ statusCode: 401, message: 'Invalid or expired token' });
  }
};

const validateDevice = [
  body('name').trim().escape().notEmpty(),
  body('location').trim().escape().notEmpty(),
  (req, _res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return next({ statusCode: 400, errors: errors.array() });
    next();
  }
];


app.post('/api/auth/register',
  authLimiter,
  body('username').isAlphanumeric().notEmpty(),
  body('password').isLength({ min: 8 }),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return next({ statusCode: 400, errors: errors.array() });

    const { username, password } = req.body;
    const user = await User.create({ username, password });
    res.status(201).json({ token: signToken(user._id) });
  }
);

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username }).select('+password');
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next({ statusCode: 400, message: 'Invalid credentials' });
  }
  user.password = undefined;
  res.json({ token: signToken(user._id), user });
});


app.put('/api/alerts', authenticate, async (req, res, next) => {
  const updated = await User.findByIdAndUpdate(
    req.user._id,
    { alertPreferences: req.body },
    { new: true, runValidators: true }
  );
  res.json(updated.alertPreferences);
});


app.get('/api/devices', authenticate, async (req, res) => {
  const filter  = req.user.role === 'admin' ? {} : { userId: req.user._id };
  const devices = await Device.find(filter).lean({ virtuals: true });
  res.json(devices);
});

app.post('/api/devices', authenticate, validateDevice, async (req, res) => {
  const device = await Device.create({ ...req.body, userId: req.user._id });
  res.status(201).json(device);
});

app.delete('/api/devices/:id', authenticate, async (req, res, next) => {
  const result = await Device.deleteOne({ _id: req.params.id, userId: req.user._id });
  if (!result.deletedCount) return next({ statusCode: 404, message: 'Device not found' });
  res.status(204).end();
});


app.get('/api/notifications', authenticate, async (req, res) => {
  const notifications = await Notification.find({ userId: req.user._id })
    .sort('-timestamp')
    .limit(50)
    .lean();
  res.json(notifications);
});

app.delete('/api/notifications/:id', authenticate, async (req, res) => {
  await Notification.deleteOne({ _id: req.params.id, userId: req.user._id });
  res.status(204).end();
});

app.delete('/api/notifications', authenticate, async (req, res) => {
  await Notification.deleteMany({ userId: req.user._id });
  res.status(204).end();
});


app.get('/api/data/historical', authenticate, async (req, res) => {
  const { range = '24h' } = req.query;
  const ranges = { '1h': 1, '24h': 24, '7d': 168 };
  const hours  = ranges[range] ?? 24;
  const from   = new Date(Date.now() - hours * 3600_000);

  const data = await SensorData.find({ userId: req.user._id, timestamp: { $gte: from } })
    .sort('-timestamp')
    .lean();
  res.json(data);
});

app.post('/api/data', authenticate, async (req, res) => {
  const { temperature, humidity } = req.body;
  const newData = await SensorData.create({ temperature, humidity, userId: req.user._id });
  io.to(req.user._id.toString()).emit('newData', newData);
  res.status(201).json(newData);
});


io.on('connection', (socket) => {
  socket.on('authenticate', async (token) => {
    try {
      const { id } = jwt.verify(token, JWT_SECRET);
      const user   = await User.findById(id);
      if (!user) throw new Error();

      const room = user._id.toString();
      socket.join(room);

      const sensorStream = SensorData.watch([
        { $match: { 'fullDocument.userId': user._id, operationType: 'insert' } }
      ]);
      sensorStream.on('change', ({ fullDocument }) => io.to(room).emit('newData', fullDocument));

      const notificationStream = Notification.watch([
        { $match: { 'fullDocument.userId': user._id, operationType: 'insert' } }
      ]);
      notificationStream.on('change', ({ fullDocument }) => io.to(room).emit('newNotification', fullDocument));

      socket.on('disconnect', () => {
        sensorStream.close();
        notificationStream.close();
      });
    } catch {
      socket.disconnect();
    }
  });
});


app.use((err, _req, res, _next) => {
  console.error(err);
  if (err.errors) return res.status(err.statusCode || 400).json({ errors: err.errors });
  res.status(err.statusCode || 500).json({ error: err.message || 'Server Error' });
});


mongoose.set('strictQuery', true);
mongoose.connect(MONGO_URI).then(() => {
  console.log('MongoDB connected');
  server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}).catch((err) => {
  console.error('Database connection failed', err);
  process.exit(1);
});

// Graceful shutdown
['SIGINT', 'SIGTERM'].forEach((sig) => process.on(sig, () => {
  server.close(() => process.exit(0));
}));

