import tkinter as tk
from tkinter import filedialog, messagebox
import os
import struct
import random
SECRET_SIZE_START_MARKER = b'SMUGGLE_DATA_SIZE_START_MARKER_'
SECRET_SIZE_END_MARKER = b'_SMUGGLE_DATA_SIZE_END_MARKER'
def encode_file(container_path, secret_path, output_path, padding_size, log_callback):
    """Encodes (smuggles) a secret file into a container file."""
    log_callback('Attempting to encode...')
    try:
        with open(container_path, 'rb') as f:
            container_data = f.read()
    except FileNotFoundError:
        log_callback(f'Error: Container file not found: {container_path}', 'red')
        return False
    except Exception as e:
        log_callback(f'Error reading container file: {e}', 'red')
        return False
    try:
        with open(secret_path, 'rb') as f:
            secret_data = f.read()
    except FileNotFoundError:
        log_callback(f'Error: Secret file not found: {secret_path}', 'red')
        return False
    except Exception as e:
        log_callback(f'Error reading secret file: {e}', 'red')
        return False
    try:
        with open(output_path, 'wb') as f:
            f.write(container_data)
            if padding_size > 0:
                log_callback(f'Adding {padding_size} bytes of random padding...')
                padding = os.urandom(padding_size)
                f.write(padding)
            f.write(SECRET_SIZE_START_MARKER)
            secret_size = len(secret_data)
            f.write(struct.pack('<Q', secret_size))
            f.write(SECRET_SIZE_END_MARKER)
            f.write(secret_data)
        final_size = os.path.getsize(output_path)
        log_callback('<font color=\'green\'><b>Encoding Successful!</b></font>')
        log_callback(f'Original container size: {len(container_data)} bytes')
        log_callback(f'Secret file size: {secret_size} bytes')
        log_callback(f'Padding added: {padding_size} bytes')
        log_callback(f'Total smuggled file size: {final_size} bytes')
        log_callback('You can smuggle up to (theoretically) your disk space minus the container file size.')
        log_callback(f'The output file \'{output_path}\' is now larger by the secret data and markers/padding.')
    except Exception as e:
        log_callback(f'Error during encoding: {e}', 'red')
        return False
    return True
def decode_file(smuggled_path, output_path, log_callback):
    """Decodes (extracts) a secret file from a smuggled file."""
    log_callback('Attempting to decode...')
    try:
        with open(smuggled_path, 'rb') as f:
            smuggled_data = f.read()
    except FileNotFoundError:
        log_callback(f'Error: Smuggled file not found: {smuggled_path}', 'red')
        return False
    except Exception as e:
        log_callback(f'Error reading smuggled file: {e}', 'red')
        return False
    start_marker_pos = smuggled_data.find(SECRET_SIZE_START_MARKER)
    if start_marker_pos == (-1):
        log_callback('Error: Secret data start marker not found in the file.', 'red')
        return False
    else:
        size_pos = start_marker_pos + len(SECRET_SIZE_START_MARKER)
        if size_pos + 8 + len(SECRET_SIZE_END_MARKER) > len(smuggled_data):
            log_callback('Error: File corrupted or incomplete after start marker.', 'red')
            return False
        else:
            try:
                secret_size_bytes = smuggled_data[size_pos:size_pos + 8]
                secret_size = struct.unpack('<Q', secret_size_bytes)[0]
            except struct.error:
                log_callback('Error: Could not unpack secret size. File might be corrupted.', 'red')
                return False
            end_marker_pos = smuggled_data.find(SECRET_SIZE_END_MARKER, size_pos + 8)
            if end_marker_pos == (-1):
                log_callback('Error: Secret data end marker not found in the file.', 'red')
                return False
            else:
                secret_data_start = end_marker_pos + len(SECRET_SIZE_END_MARKER)
                if secret_data_start + secret_size > len(smuggled_data):
                    log_callback(f'Error: Reported secret size ({secret_size} bytes) exceeds available data in the file.', 'red')
                    return False
                else:
                    extracted_secret = smuggled_data[secret_data_start:secret_data_start + secret_size]
                    try:
                        with open(output_path, 'wb') as f:
                            f.write(extracted_secret)
                        log_callback('<font color=\'green\'><b>Decoding Successful!</b></font>')
                        log_callback(f'Secret data extracted to \'{output_path}\'')
                        log_callback(f'Extracted secret file size: {len(extracted_secret)} bytes')
                    except Exception as e:
                        log_callback(f'Failed to write extracted secret data to {output_path}: {e}', 'red')
                        return False
                    return True
class SmugglerApp:
    def __init__(self, root):
        self.root = root
        root.title('File Smuggler')
        root.geometry('600x600')
        root.resizable(False, False)
        self.create_widgets()
    def create_widgets(self):
        encode_frame = tk.LabelFrame(self.root, text='Encode File', padx=10, pady=10)
        encode_frame.pack(pady=10, padx=10, fill='x')
        tk.Label(encode_frame, text='Container File:').grid(row=0, column=0, sticky='w', pady=2)
        self.container_path_entry = tk.Entry(encode_frame, width=50)
        self.container_path_entry.grid(row=0, column=1, padx=5, pady=2)
        tk.Button(encode_frame, text='Browse...', command=self.browse_container_file).grid(row=0, column=2, padx=5, pady=2)
        tk.Label(encode_frame, text='Secret File:').grid(row=1, column=0, sticky='w', pady=2)
        self.secret_path_entry = tk.Entry(encode_frame, width=50)
        self.secret_path_entry.grid(row=1, column=1, padx=5, pady=2)
        tk.Button(encode_frame, text='Browse...', command=self.browse_secret_file).grid(row=1, column=2, padx=5, pady=2)
        tk.Label(encode_frame, text='Output File:').grid(row=2, column=0, sticky='w', pady=2)
        self.encode_output_path_entry = tk.Entry(encode_frame, width=50)
        self.encode_output_path_entry.grid(row=2, column=1, padx=5, pady=2)
        tk.Button(encode_frame, text='Browse...', command=self.browse_encode_output_file).grid(row=2, column=2, padx=5, pady=2)
        tk.Label(encode_frame, text='Padding Size (bytes, optional):').grid(row=3, column=0, sticky='w', pady=2)
        self.padding_size_entry = tk.Entry(encode_frame, width=50)
        self.padding_size_entry.insert(0, '0')
        self.padding_size_entry.grid(row=3, column=1, padx=5, pady=2)
        tk.Button(encode_frame, text='Encode', command=self.encode).grid(row=4, column=1, pady=10)
        decode_frame = tk.LabelFrame(self.root, text='Decode File', padx=10, pady=10)
        decode_frame.pack(pady=10, padx=10, fill='x')
        tk.Label(decode_frame, text='Smuggled File:').grid(row=0, column=0, sticky='w', pady=2)
        self.smuggled_path_entry = tk.Entry(decode_frame, width=50)
        self.smuggled_path_entry.grid(row=0, column=1, padx=5, pady=2)
        tk.Button(decode_frame, text='Browse...', command=self.browse_smuggled_file).grid(row=0, column=2, padx=5, pady=2)
        tk.Label(decode_frame, text='Output Extracted File:').grid(row=1, column=0, sticky='w', pady=2)
        self.decode_output_path_entry = tk.Entry(decode_frame, width=50)
        self.decode_output_path_entry.grid(row=1, column=1, padx=5, pady=2)
        tk.Button(decode_frame, text='Browse...', command=self.browse_decode_output_file).grid(row=1, column=2, padx=5, pady=2)
        tk.Button(decode_frame, text='Decode', command=self.decode).grid(row=2, column=1, pady=10)
        log_frame = tk.LabelFrame(self.root, text='Messages', padx=10, pady=5)
        log_frame.pack(pady=10, padx=10, fill='both', expand=True)
        self.message_log = tk.Text(log_frame, height=10, wrap='word', state='disabled')
        self.message_log.pack(fill='both', expand=True)
        self.message_log.tag_config('red', foreground='red')
        self.message_log.tag_config('green', foreground='green')
    def log_message(self, message, color=None):
        self.message_log.config(state='normal')
        self.message_log.insert(tk.END, message + '\n', color)
        self.message_log.see(tk.END)
        self.message_log.config(state='disabled')
    def browse_container_file(self):
        file_path = filedialog.askopenfilename(title='Select Container File')
        if file_path:
            self.container_path_entry.delete(0, tk.END)
            self.container_path_entry.insert(0, file_path)
    def browse_secret_file(self):
        file_path = filedialog.askopenfilename(title='Select Secret File to Hide')
        if file_path:
            self.secret_path_entry.delete(0, tk.END)
            self.secret_path_entry.insert(0, file_path)
    def browse_encode_output_file(self):
        file_path = filedialog.asksaveasfilename(title='Save Encoded File As')
        if file_path:
            self.encode_output_path_entry.delete(0, tk.END)
            self.encode_output_path_entry.insert(0, file_path)
    def browse_smuggled_file(self):
        file_path = filedialog.askopenfilename(title='Select Smuggled File')
        if file_path:
            self.smuggled_path_entry.delete(0, tk.END)
            self.smuggled_path_entry.insert(0, file_path)
    def browse_decode_output_file(self):
        file_path = filedialog.asksaveasfilename(title='Save Extracted File As')
        if file_path:
            self.decode_output_path_entry.delete(0, tk.END)
            self.decode_output_path_entry.insert(0, file_path)
    def encode(self):
        container_path = self.container_path_entry.get()
        secret_path = self.secret_path_entry.get()
        output_path = self.encode_output_path_entry.get()
        padding_size_str = self.padding_size_entry.get()
        if not all([container_path, secret_path, output_path]):
            messagebox.showwarning('Input Error', 'Please fill all required fields for encoding.')
            return
        try:
            padding_size = int(padding_size_str) if padding_size_str else 0
            if padding_size < 0:
                raise ValueError('Padding size cannot be negative.')
        except ValueError:
            messagebox.showwarning('Input Error', 'Invalid padding size. Please enter a non-negative number.')
            return None
        self.message_log.config(state='normal')
        self.message_log.delete(1.0, tk.END)
        self.message_log.config(state='disabled')
        encode_file(container_path, secret_path, output_path, padding_size, self.log_message)
    def decode(self):
        smuggled_path = self.smuggled_path_entry.get()
        output_path = self.decode_output_path_entry.get()
        if not all([smuggled_path, output_path]):
            messagebox.showwarning('Input Error', 'Please fill all required fields for decoding.')
            return
        else:
            self.message_log.config(state='normal')
            self.message_log.delete(1.0, tk.END)
            self.message_log.config(state='disabled')
            decode_file(smuggled_path, output_path, self.log_message)
if __name__ == '__main__':
    root = tk.Tk()
    app = SmugglerApp(root)
    root.mainloop()