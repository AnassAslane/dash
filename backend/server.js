import React, { useEffect, useState, createContext, useContext } from 'react';
import { Line } from 'react-chartjs-2';
import { Chart, CategoryScale, LinearScale, PointElement, LineElement } from 'chart.js';
import { io } from 'socket.io-client';
import { ToastContainer, toast } from 'react-toastify';
import { motion, AnimatePresence } from 'framer-motion';
import 'react-toastify/dist/ReactToastify.css';
import { FiUser, FiLock, FiArrowRight, FiSun, FiDroplet, FiPlus, FiMoon, FiSettings } from 'react-icons/fi';
import './App.css';

Chart.register(CategoryScale, LinearScale, PointElement, LineElement);

const ThemeContext = createContext();
export const useTheme = () => useContext(ThemeContext);

const AuthForm = ({ onLogin }) => {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const { theme } = useTheme();

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="auth-container"
    >
      <motion.div 
        className="auth-card"
        initial={{ scale: 0.95 }}
        animate={{ scale: 1 }}
        whileHover={{ scale: 1.02 }}
      >
        <div className="auth-header">
          <motion.h1 initial={{ y: -20 }} animate={{ y: 0 }}>IoT Dashboard</motion.h1>
          <p>Monitor your connected devices</p>
        </div>
        
        <form onSubmit={(e) => {
          e.preventDefault();
          onLogin(credentials);
        }}>
          <div className="auth-input-group">
            <FiUser className="auth-icon" />
            <input
              name="username"
              value={credentials.username}
              onChange={(e) => setCredentials({...credentials, username: e.target.value})}
              placeholder="Username"
              required
            />
          </div>

          <div className="auth-input-group">
            <FiLock className="auth-icon" />
            <input
              name="password"
              type="password"
              value={credentials.password}
              onChange={(e) => setCredentials({...credentials, password: e.target.value})}
              placeholder="Password"
              required
            />
          </div>

          <motion.button 
            type="submit" 
            className="auth-submit"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Sign In <FiArrowRight className="auth-arrow" />
          </motion.button>
        </form>
      </motion.div>
    </motion.div>
  );
};

const DeviceManager = () => {
  const [newDevice, setNewDevice] = useState({ name: '', type: 'temperature', location: '' });

  const handleAddDevice = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/devices', {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newDevice)
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to add device');
      }
      
      setNewDevice({ name: '', type: 'temperature', location: '' });
      toast.success('Device added successfully');
    } catch (error) {
      console.error('Device creation error:', error);
      toast.error(error.message);
    }
  };

  return (
    <motion.div 
      className="device-manager"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <h3><FiSettings /> Device Management</h3>
      <div className="device-form">
        <input
          placeholder="Device Name"
          value={newDevice.name}
          onChange={(e) => setNewDevice({...newDevice, name: e.target.value})}
          required
        />
        <select
          value={newDevice.type}
          onChange={(e) => setNewDevice({...newDevice, type: e.target.value})}
        >
          <option value="temperature">Temperature Sensor</option>
          <option value="humidity">Humidity Sensor</option>
          <option value="motion">Motion Sensor</option>
        </select>
        <input
          placeholder="Location"
          value={newDevice.location}
          onChange={(e) => setNewDevice({...newDevice, location: e.target.value})}
          required
        />
        <motion.button 
          onClick={handleAddDevice}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <FiPlus /> Add Device
        </motion.button>
      </div>
    </motion.div>
  );
};

const AlertSettings = ({ alerts, onUpdate }) => {
  return (
    <motion.div 
      className="alert-settings"
      initial={{ scale: 0.95 }}
      animate={{ scale: 1 }}
    >
      <h3>Alert Thresholds</h3>
      <div className="alert-inputs">
        <div className="input-group">
          <FiSun />
          <input
            type="number"
            value={alerts.maxTemp}
            onChange={(e) => onUpdate({ ...alerts, maxTemp: Number(e.target.value) })}
            placeholder="Max Temperature (°C)"
            min="0"
          />
        </div>
        <div className="input-group">
          <FiDroplet />
          <input
            type="number"
            value={alerts.maxHumidity}
            onChange={(e) => onUpdate({ ...alerts, maxHumidity: Number(e.target.value) })}
            placeholder="Max Humidity (%)"
            min="0"
            max="100"
          />
        </div>
      </div>
    </motion.div>
  );
};

export default function App() {
  const [sensorData, setSensorData] = useState([]);
  const [user, setUser] = useState(null);
  const [alerts, setAlerts] = useState({ maxTemp: 30, maxHumidity: 70 });
  const [timeRange, setTimeRange] = useState('24h');
  const [theme, setTheme] = useState('light');

  const fetchHistoricalData = async (range) => {
    try {
      const response = await fetch(`http://localhost:5000/api/data/historical?range=${range}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      
      if (!response.ok) throw new Error('Failed to load data');
      
      const data = await response.json();
      setSensorData(data);
    } catch (error) {
      toast.error(error.message);
    }
  };

  const handleLogin = async (credentials) => {
    try {
      const response = await fetch('http://localhost:5000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
      });
      
      const data = await response.json();
      if (response.ok) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('userId', data.user.id);
        setUser(data.user);
        setAlerts(data.alertPreferences || alerts);
        toast.success(`Welcome ${data.user.username}!`);
      } else {
        toast.error(data.error || 'Login failed');
      }
    } catch (error) {
      toast.error('Network error. Please try again.');
    }
  };

  useEffect(() => {
    if (user) fetchHistoricalData(timeRange);
  }, [timeRange, user]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token || !user) return;

    const socket = io('http://localhost:5000', {
      auth: { token },
      transports: ['websocket']
    });

    socket.on('alert', (alert) => {
      toast.error(alert.message, { position: 'top-center' });
    });

    socket.on('newData', (newData) => {
      setSensorData(prev => [newData, ...prev.slice(0, 49)]);
    });

    return () => socket.disconnect();
  }, [user]);

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme: () => setTheme(prev => prev === 'light' ? 'dark' : 'light') }}>
      <div className={`app-container`} data-theme={theme}>
        <AnimatePresence mode='wait'>
          {!user ? (
            <AuthForm key="auth" onLogin={handleLogin} />
          ) : (
            <motion.div
              key="dashboard"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="dashboard-container"
            >
              <div className="dashboard-header">
                <h2>Welcome back, {user.username}!</h2>
                <div className="controls">
                  <motion.button 
                    onClick={() => setTheme(prev => prev === 'light' ? 'dark' : 'light')}
                    whileHover={{ scale: 1.1 }}
                    data-theme-toggle
                  >
                    {theme === 'light' ? <FiMoon /> : <FiSun />}
                  </motion.button>
                  <select 
                    value={timeRange} 
                    onChange={(e) => setTimeRange(e.target.value)}
                  >
                    <option value="1h">Last 1 Hour</option>
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                  </select>
                </div>
              </div>
              
              <div className="dashboard-content">
                <div className="sidebar">
                  <DeviceManager />
                  <AlertSettings alerts={alerts} onUpdate={setAlerts} />
                </div>
                
                <div className="main-content">
                  <div className="chart-container">
                    <Line
                      data={{
                        labels: sensorData.map(d => new Date(d.timestamp).toLocaleTimeString()),
                        datasets: [
                          {
                            label: 'Temperature (°C)',
                            data: sensorData.map(d => d.temperature),
                            borderColor: '#ff6384',
                            backgroundColor: 'rgba(255, 99, 132, 0.2)',
                            tension: 0.4
                          },
                          {
                            label: 'Humidity (%)',
                            data: sensorData.map(d => d.humidity),
                            borderColor: '#36a2eb',
                            backgroundColor: 'rgba(54, 162, 235, 0.2)',
                            tension: 0.4
                          }
                        ]
                      }}
                      options={{ 
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: {
                          duration: 1000,
                          easing: 'easeOutCubic'
                        },
                        plugins: {
                          legend: {
                            labels: {
                              color: 'var(--chart-text)'
                            }
                          }
                        },
                        scales: {
                          x: {
                            grid: { 
                              color: 'var(--chart-grid)'
                            },
                            ticks: { 
                              color: 'var(--chart-text)'
                            }
                          },
                          y: {
                            grid: { 
                              color: 'var(--chart-grid)'
                            },
                            ticks: { 
                              color: 'var(--chart-text)'
                            }
                          }
                        }
                      }}
                    />
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        <ToastContainer theme={theme} />
      </div>
    </ThemeContext.Provider>
  );
}