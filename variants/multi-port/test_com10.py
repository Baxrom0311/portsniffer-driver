import time
import sys
import os

try:
    import serial
except ImportError:
    os.system("python -m pip install pyserial")
    import serial

try:
    with serial.Serial('COM10', 115200, timeout=1) as ser:
        print("Opened COM10")
        for i in range(10):
            msg = f"TEST DATA FROM PORT SNIFFER {i}\n"
            ser.write(msg.encode())
            ser.flush()
            time.sleep(1)
        print("Done writing.")
except Exception as e:
    print(e)
