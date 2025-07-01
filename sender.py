import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import socket
import json
import os
import time
import base64
import struct
import threading
from crypto_utils import (
    generate_rsa_keys, sign_metadata, encrypt_session_key,
    add_watermark, encrypt_file, calculate_hash
)
from Crypto.PublicKey import RSA

class SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sender - Watermark Image Transfer")

        # Tạo cặp khóa RSA cho Sender
        self.private_key, self.public_key = generate_rsa_keys()

        # Tạo khóa phiên ngẫu nhiên 8 byte (dùng DES)
        self.session_key = os.urandom(8)
        self.receiver_public_key = None
        self.image_path = None

        # Giao diện
        self.label = tk.Label(root, text="Select an image to send")
        self.label.pack(pady=10)

        self.button_select = tk.Button(root, text="Select Image", command=self.select_image)
        self.button_select.pack()

        self.label_image = tk.Label(root)
        self.label_image.pack()

        self.button_send = tk.Button(root, text="Send Image", command=self.send_image)
        self.button_send.pack(pady=10)

        self.label_status = tk.Label(root, text="")
        self.label_status.pack()

        # Khu vực chat
        self.chat_label = tk.Label(root, text="Chat:")
        self.chat_label.pack(pady=5)
        self.chat_text = tk.Text(root, height=5, width=40)
        self.chat_text.pack()
        self.chat_entry = tk.Entry(root, width=40)
        self.chat_entry.pack()
        self.chat_entry.bind('<Return>', lambda event: self.send_chat())
        self.button_send_chat = tk.Button(root, text="Send Message", command=self.send_chat)
        self.button_send_chat.pack(pady=5)

        # Bắt đầu lắng nghe chat và trao đổi khóa
        self.start_chat_server()
        threading.Thread(target=self.exchange_keys, daemon=True).start()

    def select_image(self):
        """Chọn ảnh từ máy và hiển thị lên giao diện"""
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg")])
        if self.image_path:
            image = Image.open(self.image_path)
            image = image.resize((300, 300))
            self.photo = ImageTk.PhotoImage(image)
            self.label_image.config(image=self.photo)
            self.label_status.config(text="Image selected: " + self.image_path)

    def exchange_keys(self):
        """Trao đổi khóa công khai và handshake với Receiver"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(('localhost', 12345))

                # Gửi khóa công khai của Sender
                packet = json.dumps({"public_key": self.public_key.export_key().decode('utf-8')})
                s.sendall(struct.pack('!I', len(packet.encode())) + packet.encode())

                # Nhận khóa công khai của Receiver
                size_data = s.recv(4)
                size = struct.unpack('!I', size_data)[0]
                data = b""
                while len(data) < size:
                    data += s.recv(size - len(data))

                packet = json.loads(data.decode('utf-8'))
                if "receiver_public_key" in packet:
                    self.receiver_public_key = RSA.import_key(packet["receiver_public_key"])
                    self.root.after(0, lambda: self.chat_text.insert(tk.END, "Received Receiver's public key\n"))
                else:
                    raise Exception("Receiver's public key not received")

                # Gửi handshake "Hello!"
                handshake_packet = json.dumps({"handshake": "Hello!"}).encode('utf-8')
                s.sendall(struct.pack('!I', len(handshake_packet)) + handshake_packet)

                # Nhận phản hồi "Ready!"
                size_data = s.recv(4)
                size = struct.unpack('!I', size_data)[0]
                data = b""
                while len(data) < size:
                    data += s.recv(size - len(data))
                handshake_response = json.loads(data.decode('utf-8'))

                if handshake_response.get("handshake") == "Ready!":
                    self.root.after(0, lambda: self.chat_text.insert(tk.END, "Receiver: Ready!\n"))
                else:
                    raise Exception("Invalid handshake response")

        except Exception as e:
            error_msg = f"Error exchanging keys: {str(e)}"
            print(error_msg)
            self.root.after(0, lambda: self.chat_text.insert(tk.END, error_msg + "\n"))

    def start_chat_server(self):
        """Server chat (lắng nghe port 12346 để nhận tin nhắn từ Receiver)"""
        def chat_server_thread():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(('localhost', 12346))
                    s.listen()
                    print("Chat server started, listening on port 12346...")
                    while True:
                        conn, addr = s.accept()
                        with conn:
                            size = struct.unpack('!I', conn.recv(4))[0]
                            data = conn.recv(size)
                            packet = json.loads(data.decode('utf-8'))
                            self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Receiver: {packet['chat']}\n"))
                            conn.sendall("Chat received".encode('utf-8'))
                except Exception as e:
                    print(f"Chat server error: {str(e)}")

        threading.Thread(target=chat_server_thread, daemon=True).start()

    def send_chat(self):
        """Gửi tin nhắn đến Receiver thông qua port 12345"""
        message = self.chat_entry.get()
        if message:
            self.chat_text.insert(tk.END, f"Sender: {message}\n")
            self.chat_entry.delete(0, tk.END)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(('localhost', 12345))
                    packet = json.dumps({"chat": message}).encode('utf-8')
                    s.sendall(struct.pack('!I', len(packet)) + packet)
                    response = s.recv(1024).decode('utf-8')
                    self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Receiver: {response}\n"))
            except Exception as e:
                self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Error: {str(e)}\n"))

    def send_image(self):
        """Xử lý ảnh, mã hóa, ký số và gửi đến Receiver"""
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
        if not self.receiver_public_key:
            messagebox.showerror("Error", "Receiver's public key not received!")
            return

        def send_image_thread():
            try:
                print("Starting to process image...")
                watermark_text = "Copyright 2025"
                watermarked_path = "watermarked_photo.jpg"

                # Thêm watermark
                add_watermark(self.image_path, watermarked_path, watermark_text)

                # Tạo metadata và ký
                filename = os.path.basename(self.image_path)
                timestamp = str(time.time())
                metadata = f"{filename}|{timestamp}|{watermark_text}"
                signature = sign_metadata(metadata, self.private_key)

                # Mã hóa khóa phiên bằng khóa công khai của Receiver
                encrypted_session_key = encrypt_session_key(self.session_key, self.receiver_public_key)

                # Mã hóa file bằng DES
                iv, ciphertext = encrypt_file(watermarked_path, self.session_key)

                # Tính hash của dữ liệu mã hóa
                hash_value = calculate_hash(iv, ciphertext)

                # Tạo gói tin
                packet = {
                    "iv": base64.b64encode(iv).decode('utf-8'),
                    "cipher": base64.b64encode(ciphertext).decode('utf-8'),
                    "hash": hash_value,
                    "sig": base64.b64encode(signature).decode('utf-8'),
                    "metadata": metadata,
                    "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8')
                }

                # Gửi gói tin
                packet_data = json.dumps(packet).encode('utf-8')
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(10)
                    s.connect(('localhost', 12345))
                    s.sendall(struct.pack('!I', len(packet_data)) + packet_data)
                    response = s.recv(1024).decode('utf-8')

                    # Cập nhật giao diện
                    self.root.after(0, lambda: self.label_status.config(text=f"Response: {response}"))
                    self.root.after(0, lambda: self.chat_text.insert(tk.END, f"Image sent, response: {response}\n"))
                    self.root.after(0, lambda: messagebox.showinfo("Status", f"Received: {response}"))

            except Exception as e:
                error_msg = f"Error sending image: {str(e)}"
                print(error_msg)
                self.root.after(0, lambda: self.label_status.config(text=error_msg))
                self.root.after(0, lambda: self.chat_text.insert(tk.END, error_msg + "\n"))
                self.root.after(0, lambda: messagebox.showerror("Error", error_msg))

        threading.Thread(target=send_image_thread, daemon=True).start()

# Chạy giao diện
if __name__ == "__main__":
    root = tk.Tk()
    app = SenderGUI(root)
    root.geometry("400x600")
    root.mainloop()
