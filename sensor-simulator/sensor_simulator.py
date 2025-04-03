from pymongo import MongoClient
from datetime import datetime, timezone
import random
import time
import sys

def safe_connect():
    try:
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        return client
    except Exception as e:
        print("MongoDB Connection Error:", e)
        sys.exit(1)

def main():
    client = safe_connect()
    db = client.iot_data
    
    try:
        while True:
            sensor_data = {
                "temperature": round(random.uniform(20.0, 30.0), 1),
                "humidity": round(random.uniform(30.0, 70.0), 1),
                "timestamp": datetime.now(timezone.utc)
            }
            
            db.sensor_data.insert_one(sensor_data)
            print(f"Inserted: {sensor_data}")
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nSimulator stopped by user")
    except Exception as e:
        print("Critical Error:", e)
    finally:
        client.close()

if __name__ == "__main__":
    main()