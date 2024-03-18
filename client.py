import socket
import ssl
import pyaudio

# Server configuration
SERVER_HOST = '' # enter receiver ipv4 address
SERVER_PORT = 12345 # arbitrary port

def initiate_call():
    # TCP socket creation
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # SSL context creation
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.check_hostname = False
        ssl_context.load_verify_locations(cafile='server.crt') # server.crt is the cert file generated upon executing the gen_cert.py file

        # SSL handshake with server
        ssl_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=SERVER_HOST)
        ssl_client_socket.connect((SERVER_HOST, SERVER_PORT))

        # Audio setup using PyAudio   # using pyaudio to generate / mimic a call.
        p = pyaudio.PyAudio()
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100

        # Start VoIP call
        stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)

        print("VoIP call initiated. Press Ctrl+C to stop.")

        while True:
            audio_data = stream.read(CHUNK)
            ssl_client_socket.sendall(audio_data)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close resources
        stream.stop_stream()
        stream.close()
        p.terminate()
        ssl_client_socket.close()

if __name__ == '__main__':
    initiate_call()
