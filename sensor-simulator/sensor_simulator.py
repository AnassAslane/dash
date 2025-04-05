from pymongo import MongoClient
from datetime import datetime, timezone
import random
import time
import sys
import bcrypt
import getpass
from bson import ObjectId

def safe_connect():
    """Establish a safe MongoDB connection with error handling"""
    try:
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        return client
    except Exception as e:
        print("MongoDB Connection Error:", e)
        sys.exit(1)

def get_user_credentials():
    """Get username/password securely from user"""
    print("\n=== Sensor Simulator Authentication ===")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()
    return username, password

def authenticate_user(db, username, password):
    """Authenticate user against MongoDB records"""
    try:
        user = db.users.find_one({"username": username})
        if not user:
            print("Error: User not found")
            return None

        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            print("Error: Invalid password")
            return None

        return {
            "id": user['_id'],
            "alerts": user.get('alertPreferences', {
                "maxTemp": 30,
                "maxHumidity": 70
            })
        }
    except Exception as e:
        print("Authentication Error:", e)
        return None

def generate_sensor_data(user_alerts):
    """Generate sensor data with alert checks"""
    temp = round(random.uniform(20.0, 30.0), 1)
    humidity = round(random.uniform(30.0, 70.0), 1)
    alerts = []
    
    # Check temperature alert
    if temp > user_alerts['maxTemp']:
        alerts.append(f"Temperature {temp}°C exceeds {user_alerts['maxTemp']}°C")
    
    # Check humidity alert
    if humidity > user_alerts['maxHumidity']:
        alerts.append(f"Humidity {humidity}% exceeds {user_alerts['maxHumidity']}%")
    
    return {
        "temperature": temp,
        "humidity": humidity,
        "timestamp": datetime.now(timezone.utc),
        "alerts": alerts
    }

def main():
    client = safe_connect()
    db = client.iot_data
    
    # User authentication
    username, password = get_user_credentials()
    user = authenticate_user(db, username, password)
    if not user:
        client.close()
        return

    try:
        print(f"\n=== Starting simulator for user: {username} ===")
        print(f"Alert Thresholds - Temp: {user['alerts']['maxTemp']}°C, Humidity: {user['alerts']['maxHumidity']}%")
        
        while True:
            # Generate and insert data
            sensor_data = generate_sensor_data(user['alerts'])
            db.sensor_data.insert_one({
                **sensor_data,
                "userId": ObjectId(user['id'])
            })
            
            # Print alerts if any
            if sensor_data['alerts']:
                print(f"\n⚠️  ALERTS DETECTED ⚠️")
                for alert in sensor_data['alerts']:
                    print(f" - {alert}")
                
            print(f"Inserted: {sensor_data['temperature']}°C, {sensor_data['humidity']}%")
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\n=== Simulator stopped by user ===")
    except Exception as e:
        print("\nCRITICAL ERROR:", e)
    finally:
        client.close()

if __name__ == "__main__":
    main()