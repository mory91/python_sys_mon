import psutil
import time

read_bytes = 0
buffer = []
while True:
    time.sleep(0.03)
    new_read_bytes = psutil.disk_io_counters().read_bytes
    buffer.append(new_read_bytes - read_bytes)
    read_bytes = new_read_bytes
    if len(buffer) >= 100:
        with open('data.txt', 'a') as f:
            for num in buffer:
                f.write(f"{num}\n")
        buffer.clear()

