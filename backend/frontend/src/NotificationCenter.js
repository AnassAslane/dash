import { io } from 'socket.io-client';
import { useEffect, useState } from 'react';
import { FiBell } from 'react-icons/fi';

export default function NotificationCenter() {
  const [notifications, setNotifications] = useState([]);
  const token = localStorage.getItem('token');

  useEffect(() => {
    const socket = io('http://localhost:5000', {
      auth: { token }
    });

    socket.on('real-time-notification', (notification) => {
      setNotifications(prev => [notification, ...prev.slice(0, 9)]); // Keep last 10
    });

    return () => socket.disconnect();
  }, [token]);

  return (
    <div className="notification-center">
      <h3><FiBell /> Notifications ({notifications.length})</h3>
      <div className="notification-list">
        {notifications.map((n, i) => (
          <div key={i} className={`notification-item ${n.type || 'info'}`}>
            <p>{n.message}</p>
            <small>{new Date(n.timestamp).toLocaleString()}</small>
          </div>
        ))}
      </div>
    </div>
  );
}