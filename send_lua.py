import sys
import socket
import struct
import binascii

signals = {
    4: "SIGILL",
    10: "SIGBUS",
    11: "SIGSEGV",
}

def send_payload(ip, port, filepath):
    data = open(filepath, "rb").read()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:        
        sock.connect((ip, int(port)))
        
        # send size (qword) + <buffer..>
        size = struct.pack("<Q", len(data))   # little endian
        sock.sendall(size + data)

        response = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.append(chunk)

            if len(chunk) == 8 or len(chunk) == 16:
                break

        response = b''.join(response)
        if len(response) == 16:
            crash_code_data = struct.unpack("<Q", response[:8])[0]
            crash_code = signals.get(crash_code_data, f"Unknown signal code {crash_code_data}")
            
            crash_address_data = struct.unpack("<Q", response[8:])[0]
            crash_address = f"0x{crash_address_data:016x}"
            
            print(f"{crash_code} at {crash_address}")
        elif len(response) == 8:
            crash_address = binascii.hexlify(bytes(reversed(response))).decode('utf-8')
            print(f"Crash at 0x{crash_address}")
        else:
            print(response.decode("utf-8"))

def main():
    if len(sys.argv) != 4:
        print("{} <ps-ip> <port> <filepath>".format(sys.argv[0]))
        return

    ip, port, filepath = sys.argv[1:]
    send_payload(ip, port, filepath)

if __name__ == "__main__":
    main()
