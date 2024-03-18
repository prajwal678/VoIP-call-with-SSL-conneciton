import socket
import ssl
import subprocess
import threading
import scapy.all as scapy
import sys
import pyaudio
import wave
import os
import time

# SSL certification files, change name as per in the gen_cert.py file
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

# Server configuration
HOST = ''   # receiver ipv4 address
PORT = 12345

ssl_context = None
client_sockets = []

def save_audio_data(audio_data):
    with open("received_audio.wav", "ab") as audio_file:
        audio_file.write(audio_data)

# Function to start packet capture using tshark
def start_packet_capture():
    pcap_file = 'voip_call_capture.pcap'
    capture_command = f"tshark -i en0 -w {pcap_file}"
    subprocess.Popen(capture_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    print("Packet capture has started.")

    time.sleep(10)  # Adjust the duration as needed (size of audio file)
    subprocess.run(['pkill', 'tshark'])

    # Analyze captured packets
    analyze_packets(pcap_file) # wireshark

def analyze_packets(pcap_file):
    # Read the captured packets
    packets = scapy.rdpcap(pcap_file)

    # Extract relevant information (e.g., source IP addresses, packet sizes)
    source_ips = []
    packet_sizes = []

    for packet in packets:
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):
            source_ips.append(packet[scapy.IP].src)
            packet_sizes.append(len(packet))

    # Open the PCAP file in Wireshark for analysis
    os.system(f"wireshark {pcap_file}")

def handle_client(client_socket, client_addr):
    ssl_client_socket = ssl_context.wrap_socket(client_socket, server_side=True)

    p = pyaudio.PyAudio()
    CHUNK = 1024
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 44100

    wf = wave.open("received_audio.wav", 'wb')
    wf.setnchannels(CHANNELS)
    wf.setsampwidth(p.get_sample_size(FORMAT))
    wf.setframerate(RATE)

    try:
        while True:
            audio_data = ssl_client_socket.recv(CHUNK)
            if not audio_data:
                break
            save_audio_data(audio_data)
            wf.writeframes(audio_data)
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        # CLose resources
        wf.close()
        ssl_client_socket.close()
        p.terminate()

def broadcast_audio_data(audio_data, sender_socket):
    for client_socket in client_sockets:
        if client_socket != sender_socket:
            try:
                client_socket.sendall(audio_data)
            except Exception as e:
                print(f"Error broadcasting data to a client: {e}")

def main():
    global ssl_context, client_sockets
    try:
        # Load SSL context with certificate and key to establish and verify SSL connection
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

        # Create TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)

        print(f"Server listening on {HOST}:{PORT}")

        # Start packet capture in a separate thread
        capture_thread = threading.Thread(target=start_packet_capture)
        capture_thread.start()

        client_sockets = []

        while True:
            client_socket, client_addr = server_socket.accept()
            print(f"New connection from {client_addr}")
            client_sockets.append(client_socket)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            client_thread.start()

            # Start a thread to handle broadcasting audio data to all clients
            broadcast_thread = threading.Thread(target=broadcast_audio_data, args=(b"New client joined.", client_socket))
            broadcast_thread.start()

    except KeyboardInterrupt:
        print("KeyboardInterrupt: Server shutting down.")
        server_socket.close()
        sys.exit(0)

if __name__ == '__main__':
    main()
