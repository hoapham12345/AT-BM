import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import socket
import json
import base64
import struct
import threading
from crypto_utils import verify_signature, decrypt_session_key, verify_hash, decrypt_file, generate_rsa_keys
from Crypto.PublicKey import RSA

class ReceiverGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Receiver - Watermark Image Transfer")

        # Tạo cặp khóa RSA cho bên nhận
        self.private_key, self.public_key = generate_rsa_keys()
        self.sender_public_key = None  # Sẽ nhận sau khi bắt tay

        # Các thành phần giao diện
        self.label = tk.Label(root, text="Waiting for image...")
        self.label.pack(pady=10)
        
        self.label_image = tk.Label(root)
        self.label_image.pack()
        
        self.label_status = tk.Label(root, text="")
        self.label_status.pack()

        # Phần chat
        self.chat_label = tk.Label(root, text="Chat:")
        self.chat_label.pack(pady=5)
        self.chat_text = tk.Text(root, height=5, width=40)
        self.chat_text.pack()
        self.chat_entry = tk.Entry(root, width=40)
        self.chat_entry.pack()
        self.chat_entry.bind('<Return>', lambda event: self.send_chat())
        self.button_send_chat = tk.Button(root, text="Send Message", command=self.send_chat)
        self.button_send_chat.pack(pady=5)

        self.start_server()  # Bắt đầu server để nhận dữ liệu

    def send_chat(self):
        """
        Gửi tin nhắn chat đến sender qua cổng 12346
        """
        message = self.chat_entry.get()
        if message:
            self.chat_text.insert(tk.END, f"Receiver: {message}\n")
            self.chat_entry.delete(0, tk.END)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(('localhost', 12346))
                    packet = json.dumps({"chat": message})
                    packet_data = packet.encode('utf-8')
                    print(f"Sending chat packet: {packet}")
                    s.sendall(struct.pack('!I', len(packet_data)) + packet_data)
                    response = s.recv(1024).decode('utf-8')
                    self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Sender: {response}\n"))
            except Exception as e:
                self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Error: {str(e)}\n"))

    def start_server(self):
        """
        Hàm chạy server socket ở cổng 12345 để nhận file ảnh, khóa, chữ ký, handshake, tin nhắn...
        """
        def server_thread():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(('localhost', 12345))
                    s.listen()
                    print("Server started, listening on port 12345...")
                    while True:
                        conn, addr = s.accept()
                        print(f"Connected by {addr}")
                        with conn:
                            try:
                                # Nhận độ dài gói dữ liệu đầu tiên
                                size_data = conn.recv(4)
                                if not size_data:
                                    print("No data received, closing connection")
                                    continue
                                size = struct.unpack('!I', size_data)[0]

                                # Nhận nội dung gói dữ liệu
                                data = b""
                                while len(data) < size:
                                    chunk = conn.recv(size - len(data))
                                    if not chunk:
                                        raise Exception("Incomplete data received")
                                    data += chunk
                                print(f"Raw data received: {data.hex()}")

                                # Giải mã gói JSON
                                try:
                                    packet = json.loads(data.decode('utf-8'))
                                except UnicodeDecodeError as e:
                                    print(f"UTF-8 decode error: {str(e)}")
                                    conn.sendall(f"Error: UTF-8 decode error: {str(e)}".encode('utf-8'))
                                    continue

                                # Xử lý gói theo nội dung
                                if "public_key" in packet:
                                    # Nhận khóa công khai của sender
                                    self.sender_public_key = RSA.import_key(packet["public_key"])
                                    self.root.after(0, lambda: self.chat_text.insert(tk.END, "Received Sender's public key\n"))

                                    # Gửi lại khóa công khai của receiver
                                    response_packet = json.dumps({"receiver_public_key": self.public_key.export_key().decode('utf-8')})
                                    response_data = response_packet.encode('utf-8')
                                    print(f"Sending receiver public key: {response_packet}")
                                    conn.sendall(struct.pack('!I', len(response_data)) + response_data)
                                    
                                    # Tiếp tục nhận gói handshake
                                    size_data = conn.recv(4)
                                    if not size_data:
                                        print("No handshake message received")
                                        conn.sendall("Error: No handshake message received".encode('utf-8'))
                                        continue
                                    size = struct.unpack('!I', size_data)[0]
                                    data = b""
                                    while len(data) < size:
                                        chunk = conn.recv(size - len(data))
                                        if not chunk:
                                            raise Exception("Incomplete handshake message received")
                                        data += chunk
                                    print(f"Raw handshake message: {data.hex()}")
                                    handshake_packet = json.loads(data.decode('utf-8'))
                                    if "handshake" in handshake_packet and handshake_packet["handshake"] == "Hello!":
                                        self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Sender: {handshake_packet['handshake']}\n"))
                                        # Gửi phản hồi handshake
                                        response_packet = json.dumps({"handshake": "Ready!"})
                                        response_data = response_packet.encode('utf-8')
                                        print(f"Sending handshake response: {response_packet}")
                                        conn.sendall(struct.pack('!I', len(response_data)) + response_data)
                                    else:
                                        conn.sendall("Error: Invalid handshake message".encode('utf-8'))

                                elif "chat" in packet:
                                    # Tin nhắn chat từ sender
                                    self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Sender: {packet['chat']}\n"))
                                    conn.sendall("Chat received".encode('utf-8'))
                                else:
                                    # Gói dữ liệu chứa ảnh và thông tin bảo mật
                                    response = self.process_packet(packet)
                                    conn.sendall(response.encode('utf-8'))
                                    self.root.after(0, self.update_gui, response)
                            except Exception as e:
                                print(f"Connection error: {str(e)}")
                                conn.sendall(f"Error: {str(e)}".encode('utf-8'))
                except Exception as e:
                    print(f"Server error: {str(e)}")
                    self.root.after(0, lambda: self.label_status.config(text=f"Server error: {str(e)}"))

        threading.Thread(target=server_thread, daemon=True).start()

    def process_packet(self, packet):
        """
        Xử lý gói tin chứa ảnh đã mã hóa, khóa phiên, chữ ký, hash...
        """
        print("Processing packet:", packet.keys())
        try:
            if not self.sender_public_key:
                print("Error: Sender's public key not received")
                return "NACK: Sender's public key not received"
            
            # Giải mã các trường trong gói tin
            iv = base64.b64decode(packet["iv"])
            ciphertext = base64.b64decode(packet["cipher"])
            hash_value = packet["hash"]
            signature = base64.b64decode(packet["sig"])
            metadata = packet["metadata"]
            encrypted_session_key = base64.b64decode(packet["encrypted_session_key"])

            # Xác minh chữ ký và hash
            print("Verifying signature...")
            sig_verified = verify_signature(metadata, signature, self.sender_public_key)
            print("Verifying hash...")
            hash_verified = verify_hash(iv, ciphertext, hash_value)
            
            if sig_verified and hash_verified:
                print("Signature and hash verified, decrypting session key...")
                session_key = decrypt_session_key(encrypted_session_key, self.private_key)
                if not session_key or len(session_key) != 8:  # DES: 8 bytes key
                    print(f"Invalid session key: {session_key}")
                    return f"NACK: Invalid session key length ({len(session_key) if session_key else 0} bytes)"
                print("Decrypting file...")
                decrypt_file(iv, ciphertext, session_key, "received_photo.jpg")
                print("Image decrypted and saved")
                return "ACK"
            else:
                print(f"Verification failed: Signature={sig_verified}, Hash={hash_verified}")
                return f"NACK: Signature={sig_verified}, Hash={hash_verified}"
        except Exception as e:
            print(f"Error in process_packet: {str(e)}")
            return f"NACK: {str(e)}"

    def update_gui(self, response):
        """
        Cập nhật giao diện sau khi xử lý gói dữ liệu
        """
        self.label_status.config(text=f"Response: {response}")
        if response == "ACK":
            # Hiển thị ảnh nếu kiểm tra thành công
            image = Image.open("received_photo.jpg")
            image = image.resize((300, 300))
            self.photo = ImageTk.PhotoImage(image)
            self.label_image.config(image=self.photo)
            self.chat_text.insert(tk.END, "Image received successfully\n")
            messagebox.showinfo("Success", "Image received and verified!")
        else:
            self.chat_text.insert(tk.END, f"Image verification failed: {response}\n")
            messagebox.showerror("Error", f"Integrity check failed: {response}")

# Khởi động chương trình
if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverGUI(root)
    root.geometry("400x600")
    root.mainloop()
