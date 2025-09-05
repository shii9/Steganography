#!/usr/bin/env python3
"""
Run: python3 stegui_capacity.py
A GUI application to hide/extract text, image, 
or audio files inside PNG/JPEG images using LSB steganography.
Supports optional zlib compression and password-based encryption(Fernet).

"""

import os
import threading
import base64
import zlib
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# -------------------------
# Bit helpers
# -------------------------
def _bytes_to_bits(data: bytes):
    """Return list of bits MSB-first for each byte."""
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]

def _bits_to_bytes(bits):
    """Convert list of bits to bytes (MSB-first)."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)

# -------------------------
# Key derivation (PBKDF2)
# -------------------------
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=200_000,
                     backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

# -------------------------
# Payload format + flags
# Format:
# [4-byte length][flags:1][if flags&ENC: salt(16) ][body...]
# flags bitfield:
#  0x80 = encrypted
#  0x40 = compressed (zlib)
# body when not encrypted: [kind:1][data...]
# body when encrypted: Fernet.encrypt([kind:1][data...]) (salt precedes ciphertext)
# kind: 0=text, 1=image, 2=audio
# -------------------------
ENC_MASK = 0x80
CMP_MASK = 0x40

def build_payload(kind: int, data: bytes, password: str = None, compress: bool = False) -> bytes:
    """Build full payload blob with header and optional compression/encryption."""
    flags = 0
    payload_data = data
    if compress:
        payload_data = zlib.compress(payload_data)
        flags |= CMP_MASK
    body_plain = bytes([kind]) + payload_data
    if password:
        flags |= ENC_MASK
        salt = os.urandom(16)
        key = derive_key_from_password(password, salt)
        f = Fernet(key)
        ciphertext = f.encrypt(body_plain)
        blob = bytes([flags]) + salt + ciphertext
    else:
        blob = bytes([flags]) + body_plain
    header = len(blob).to_bytes(4, "big")
    return header + blob

def parse_payload(blob: bytes, password: str = None):
    """Parse payload blob and return (kind, data bytes). Raises on errors."""
    if len(blob) < 1:
        raise ValueError("Empty payload.")
    flags = blob[0]
    if flags & ENC_MASK:
        if len(blob) < 17:
            raise ValueError("Invalid encrypted payload.")
        salt = blob[1:17]
        ciphertext = blob[17:]
        if not password:
            raise ValueError("Password required to decrypt.")
        key = derive_key_from_password(password, salt)
        f = Fernet(key)
        try:
            decrypted = f.decrypt(ciphertext)
        except Exception as e:
            raise ValueError("Decryption failed. Wrong password or corrupted data.") from e
        if len(decrypted) < 1:
            raise ValueError("Decrypted payload invalid.")
        kind = decrypted[0]
        data = decrypted[1:]
    else:
        if len(blob) < 2:
            raise ValueError("Invalid payload.")
        kind = blob[1]
        data = blob[2:]
    if flags & CMP_MASK:
        try:
            data = zlib.decompress(data)
        except Exception as e:
            raise ValueError("Decompression failed or data corrupted.") from e
    return kind, data

# -------------------------
# LSB embed / extract with variable bits-per-channel (lsb)
# -------------------------
def embed_payload_in_image(img: Image.Image, payload: bytes, lsb: int = 1) -> Image.Image:
    """
    Embed payload bytes into image LSBs using 'lsb' bits per color channel.
    lsb must be 1..3. Returns new PIL Image (RGB).
    """
    if not (1 <= lsb <= 3):
        raise ValueError("lsb must be 1, 2 or 3.")
    img_rgb = img.convert("RGB")
    W, H = img_rgb.size
    pixels = list(img_rgb.getdata())
    flat = [c for px in pixels for c in px]  # flatten channels
    bits = _bytes_to_bits(payload)
    capacity = len(flat) * lsb
    if len(bits) > capacity:
        raise ValueError(f"Payload too large for this image.\nPayload: {len(payload)} bytes ({len(bits)} bits), Capacity: {capacity//8} bytes ({capacity} bits) with {lsb} LSB(s).")
    # embed bits in groups of 'lsb' into each channel
    mask = (1 << lsb) - 1
    bit_index = 0
    for i in range(len(flat)):
        if bit_index >= len(bits):
            break
        # collect next lsb bits (MSB-first within chunk)
        chunk = bits[bit_index: bit_index + lsb]
        # if chunk shorter than lsb, pad with zeros (shouldn't happen because we check capacity)
        if len(chunk) < lsb:
            chunk = chunk + [0] * (lsb - len(chunk))
        val = 0
        for b in chunk:
            val = (val << 1) | b
        flat[i] = (flat[i] & (~mask)) | val
        bit_index += lsb
    # remaining channels unchanged
    new_pixels = [tuple(flat[i:i+3]) for i in range(0, len(flat), 3)]
    out = Image.new("RGB", (W, H))
    out.putdata(new_pixels)
    return out

def extract_payload_from_image(img: Image.Image, lsb: int = 1) -> bytes:
    """
    Extract payload bytes from image using the 4-byte length header.
    lsb must match the embedding depth used earlier.
    Returns the payload blob (flags + optional salt + body).
    """
    if not (1 <= lsb <= 3):
        raise ValueError("lsb must be 1, 2 or 3.")
    img_rgb = img.convert("RGB")
    pixels = list(img_rgb.getdata())
    flat = [c for px in pixels for c in px]
    mask = (1 << lsb) - 1
    # read first 32 bits for header using groups with lsb depth
    header_bits = []
    bits_needed_for_header = 32
    # gather bits sequentially
    for channel_value in flat:
        val = channel_value & mask
        # split val into 'lsb' bits MSB-first
        for j in range(lsb-1, -1, -1):
            header_bits.append((val >> j) & 1)
            if len(header_bits) >= bits_needed_for_header:
                break
        if len(header_bits) >= bits_needed_for_header:
            break
    if len(header_bits) < bits_needed_for_header:
        raise ValueError("Image too small or corrupted (cannot read header).")
    payload_len = 0
    for b in header_bits:
        payload_len = (payload_len << 1) | b
    total_bits_needed = 32 + payload_len * 8
    capacity = len(flat) * lsb
    if payload_len <= 0 or total_bits_needed > capacity:
        raise ValueError("Invalid payload length or corrupted stego image.")
    # collect payload bits
    payload_bits = []
    bits_collected = 0
    # we've already consumed some channels for header; determine starting channel index
    channels_for_header = (bits_needed_for_header + lsb - 1) // lsb
    for i in range(channels_for_header, len(flat)):
        val = flat[i] & mask
        # append MSB-first bits
        for j in range(lsb-1, -1, -1):
            payload_bits.append((val >> j) & 1)
            bits_collected += 1
            if bits_collected >= payload_len * 8:
                break
        if bits_collected >= payload_len * 8:
            break
    return _bits_to_bytes(payload_bits)

# -------------------------
# GUI Application
# -------------------------
class StegApp:
    def __init__(self, root):
        self.root = root
        root.title("LSB Stego — Hide Text / Image / Audio (with compression & LSB depth)")
        root.geometry("980x580")
        root.minsize(760, 480)
        root.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)

        # state
        self.open_path = None
        self.original_image = None
        self.stego_image = None
        self.preview_imgtk = None

        self.payload_kind = 0  # 0=text,1=image,2=audio
        self.payload_data = None
        self.payload_filename = None

        self._create_styles()
        self._build_layout()
        self.left_frame.bind("<Configure>", self._on_left_configure)

    def _create_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 13, "bold"))
        style.configure("Small.TLabel", font=("Segoe UI", 9))

    def _build_layout(self):
        self.main_pane = PanedWindow(self.root, orient=HORIZONTAL)
        self.main_pane.grid(row=0, column=0, sticky="nsew")

        self.left_frame = ttk.Frame(self.main_pane)
        self.right_frame = ttk.Frame(self.main_pane, width=360)
        self.main_pane.add(self.left_frame, stretch="always")
        self.main_pane.add(self.right_frame)

        self._build_left_frame()
        self._build_right_frame()

    # -------------------------
    # Left: preview + open/save
    # -------------------------
    def _build_left_frame(self):
        lf = self.left_frame
        lf.rowconfigure(2, weight=1)
        lf.columnconfigure(0, weight=1)

        ttk.Label(lf, text="Cover Image Preview", style="Header.TLabel").grid(row=0, column=0, sticky="w", padx=12, pady=(10,6))
        self.preview_canvas = Canvas(lf, bg="#111", highlightthickness=1, highlightbackground="#444")
        self.preview_canvas.grid(row=2, column=0, sticky="nsew", padx=12, pady=(6,12))

        ctrl_frame = ttk.Frame(lf)
        ctrl_frame.grid(row=3, column=0, sticky="ew", padx=12, pady=(0,12))
        ctrl_frame.columnconfigure(0, weight=1)
        ctrl_frame.columnconfigure(1, weight=0)
        ctrl_frame.columnconfigure(2, weight=0)

        self.open_btn = Button(ctrl_frame, text="Open Image", bg="#0a5cff", fg="white",
                               font=("Segoe UI", 11, "bold"), width=18, height=1,
                               command=self.open_image)
        self.open_btn.grid(row=0, column=0, sticky="w", padx=(0,8))

        self.clear_btn = ttk.Button(ctrl_frame, text="Clear", command=self.clear_preview)
        self.clear_btn.grid(row=0, column=1, padx=6)

        self.save_btn = Button(ctrl_frame, text="Save Stego", bg="#2196F3", fg="white", width=12,
                               command=self.save_stego, state="disabled")
        self.save_btn.grid(row=0, column=2, padx=6)

        ttk.Label(lf, text="Selected file path:", style="Small.TLabel").grid(row=4, column=0, sticky="w", padx=12)
        self.path_label = ttk.Label(lf, text="(no file selected)", anchor="w", justify="left", wraplength=1000)
        self.path_label.grid(row=5, column=0, sticky="w", padx=12, pady=(2,8))

    # -------------------------
    # Right: payload controls, compression & LSB depth
    # -------------------------
    def _build_right_frame(self):
        rf = self.right_frame
        rf.pack_propagate(False)
        rf.columnconfigure(0, weight=1)

        ttk.Label(rf, text="Secret payload", style="Header.TLabel").grid(row=0, column=0, sticky="w", padx=12, pady=(12,6))

        # payload kind
        self.kind_var = IntVar(value=0)
        types_frame = ttk.Frame(rf)
        types_frame.grid(row=1, column=0, sticky="w", padx=12)
        Radiobutton(types_frame, text="Text", variable=self.kind_var, value=0, command=self._on_kind_change).grid(row=0, column=0, sticky="w")
        Radiobutton(types_frame, text="Image (PNG/JPG)", variable=self.kind_var, value=1, command=self._on_kind_change).grid(row=0, column=1, sticky="w", padx=(8,0))
        Radiobutton(types_frame, text="Audio (WAV/MP3)", variable=self.kind_var, value=2, command=self._on_kind_change).grid(row=0, column=2, sticky="w", padx=(8,0))

        # text input
        ttk.Label(rf, text="Text message:", style="Small.TLabel").grid(row=2, column=0, sticky="w", padx=12, pady=(8,2))
        self.text_box = Text(rf, wrap="word", font=("Segoe UI", 10), height=8)
        self.text_box.grid(row=3, column=0, sticky="ew", padx=12, pady=(0,8))

        # file loader for image/audio
        file_frame = ttk.Frame(rf)
        file_frame.grid(row=4, column=0, sticky="ew", padx=12)
        self.load_file_btn = Button(file_frame, text="Load Image/Audio File", bg="#6A1B9A", fg="white",
                                    command=self.load_payload_file)
        self.load_file_btn.grid(row=0, column=0, sticky="ew")
        self.payload_label = ttk.Label(file_frame, text="(no file loaded)", style="Small.TLabel")
        self.payload_label.grid(row=1, column=0, sticky="w", pady=(6,0))

        # compression checkbox
        self.compress_var = IntVar(value=1)
        ttk.Checkbutton(rf, text="Compress payload (zlib) — usually reduces size", variable=self.compress_var).grid(row=5, column=0, sticky="w", padx=12, pady=(8,2))

        # LSB depth selection
        ttk.Label(rf, text="LSB depth (bits per channel):", style="Small.TLabel").grid(row=6, column=0, sticky="w", padx=12, pady=(8,2))
        self.lsb_var = IntVar(value=1)
        lsb_frame = ttk.Frame(rf)
        lsb_frame.grid(row=7, column=0, sticky="w", padx=12)
        Radiobutton(lsb_frame, text="1 (best quality)", variable=self.lsb_var, value=1).grid(row=0, column=0, sticky="w")
        Radiobutton(lsb_frame, text="2 (more capacity)", variable=self.lsb_var, value=2).grid(row=0, column=1, sticky="w", padx=(8,0))
        Radiobutton(lsb_frame, text="3 (max capacity)", variable=self.lsb_var, value=3).grid(row=0, column=2, sticky="w", padx=(8,0))

        # password
        ttk.Label(rf, text="Optional password (encrypt / decrypt)", style="Small.TLabel").grid(row=8, column=0, sticky="w", padx=12, pady=(8,2))
        self.pw_var = StringVar()
        self.pw_entry = Entry(rf, textvariable=self.pw_var, show="*", font=("Segoe UI", 10))
        self.pw_entry.grid(row=9, column=0, sticky="ew", padx=12, pady=(0,8))

        # capacity & status
        self.capacity_label = ttk.Label(rf, text="Image capacity: N/A", style="Small.TLabel")
        self.capacity_label.grid(row=10, column=0, sticky="w", padx=12)
        self.status_var = StringVar(value="Ready")
        ttk.Label(rf, textvariable=self.status_var, style="Small.TLabel").grid(row=11, column=0, sticky="w", padx=12, pady=(6,8))

        # action buttons
        btns = ttk.Frame(rf)
        btns.grid(row=12, column=0, pady=6, padx=12)
        self.encode_btn = Button(btns, text="Encode (Hide)", bg="#4CAF50", fg="white", width=14, command=self.threaded_encode)
        self.encode_btn.grid(row=0, column=0, padx=6)
        self.decode_btn = Button(btns, text="Decode (Extract)", bg="#FF9800", fg="white", width=14, command=self.threaded_decode)
        self.decode_btn.grid(row=0, column=1, padx=6)

        # progress bar
        self.progress = ttk.Progressbar(rf, orient="horizontal", length=260, mode="determinate")
        self.progress.grid(row=13, column=0, padx=12, pady=(12,8))

        # tips
        ttk.Label(rf, text="Tips (short):", style="Small.TLabel").grid(row=14, column=0, sticky="w", padx=12, pady=(8,0))
        ttk.Label(rf, text="- Use PNG (lossless) for stego files.\n- If you encrypt, share the password out-of-band.\n- Increasing LSBs increases capacity but may degrade image quality.",
                  wraplength=320, justify="left").grid(row=15, column=0, sticky="w", padx=12, pady=(4,12))

        self._on_kind_change()  # set initial UI state

    # -------------------------
    # UI callbacks
    # -------------------------
    def _on_kind_change(self):
        k = self.kind_var.get()
        if k == 0:
            # text primary
            self.text_box.configure(state="normal")
            self.load_file_btn.configure(state="disabled")
            self.payload_label.configure(text="(no file loaded)")
            self.payload_data = None
            self.payload_kind = 0
            self.payload_filename = None
        else:
            self.text_box.configure(state="normal")
            self.load_file_btn.configure(state="normal")
            self.payload_data = None
            self.payload_kind = k
            self.payload_filename = None
            self.payload_label.configure(text="(no file loaded)")

    def open_image(self):
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.isdir(desktop):
            desktop = os.path.expanduser("~")
        path = filedialog.askopenfilename(title="Select image file",
                                          initialdir=desktop,
                                          filetypes=[("PNG images", "*.png"),
                                                     ("JPEG images", "*.jpg;*.jpeg"),
                                                     ("BMP images", "*.bmp"),
                                                     ("All files", "*.*")])
        if not path:
            return
        try:
            img = Image.open(path)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open image:\n{e}")
            return
        self.open_path = path
        self.original_image = img.convert("RGB")
        self.stego_image = None
        self.save_btn.configure(state="disabled")
        self.show_preview(self.original_image)
        self.update_capacity_label(self.original_image)
        self.path_label.configure(text=path)
        self.status_var.set("Image loaded.")

    def show_preview(self, pil_img: Image.Image):
        if pil_img is None:
            self.preview_canvas.delete("all")
            return
        self._preview_source = pil_img.copy()
        cw = max(200, self.preview_canvas.winfo_width())
        ch = max(120, self.preview_canvas.winfo_height())
        thumb = pil_img.copy()
        thumb.thumbnail((cw - 8, ch - 8), Image.LANCZOS)
        self.preview_imgtk = ImageTk.PhotoImage(thumb)
        self.preview_canvas.delete("all")
        self.preview_canvas.create_image(cw // 2, ch // 2, image=self.preview_imgtk, anchor="center")
        self.preview_canvas.image = self.preview_imgtk

    def _on_left_configure(self, event):
        self.root.after(50, self._refresh_preview_on_resize)

    def _refresh_preview_on_resize(self):
        if hasattr(self, "_preview_source") and self._preview_source:
            self.show_preview(self._preview_source)

    def clear_preview(self):
        self.open_path = None
        self.original_image = None
        self.preview_canvas.delete("all")
        self.preview_canvas.image = None
        self.path_label.configure(text="(no file selected)")
        self.capacity_label.configure(text="Image capacity: N/A")
        self.status_var.set("Ready")
        self.save_btn.configure(state="disabled")
        self.stego_image = None
        self.progress["value"] = 0
        self.text_box.delete("1.0", END)
        # keep password — cleared only after successful encode/decode

    def update_capacity_label(self, pil_img):
        W, H = pil_img.size
        lsb = self.lsb_var.get()
        capacity_bits = W * H * 3 * lsb
        capacity_bytes = capacity_bits // 8
        self.capacity_label.configure(text=f"Image capacity: {capacity_bytes:,} bytes ({capacity_bits:,} bits) with {lsb} LSB(s)")

    # -------------------------
    # Load payload file (image/audio)
    # -------------------------
    def load_payload_file(self):
        path = filedialog.askopenfilename(title="Select secret file",
                                          filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp"),
                                                     ("Audio", "*.wav;*.mp3;*.ogg;*.flac"),
                                                     ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file:\n{e}")
            return
        ext = os.path.splitext(path)[1].lower()
        k = self.kind_var.get()
        # Accept load regardless of extension; warn minimal mismatch
        self.payload_data = data
        self.payload_kind = k
        self.payload_filename = os.path.basename(path)
        self.payload_label.configure(text=f"Loaded: {self.payload_filename}")

    # -------------------------
    # Encode / decode (threaded)
    # -------------------------
    def threaded_encode(self):
        threading.Thread(target=self.encode_action, daemon=True).start()

    def encode_action(self):
        if not self.original_image:
            messagebox.showwarning("No image", "Please select a cover image first.")
            return

        kind_selected = self.kind_var.get()
        password = self.pw_var.get().strip() or None
        compress = bool(self.compress_var.get())
        lsb = int(self.lsb_var.get())

        # prepare payload bytes & kind
        if kind_selected == 0:
            text = self.text_box.get("1.0", END).rstrip("\n")
            if text == "":
                messagebox.showwarning("No message", "Please enter a message to hide (or choose a different payload type).")
                return
            data = text.encode("utf-8")
            kind = 0
        else:
            if not self.payload_data:
                messagebox.showwarning("No file", "Please load an image or audio file as the secret payload.")
                return
            data = self.payload_data
            kind = kind_selected

        # build payload (with compression & optional encryption)
        try:
            payload = build_payload(kind, data, password=password, compress=compress)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to prepare payload:\n{e}")
            return

        # check capacity using the chosen LSB depth
        W, H = self.original_image.size
        max_bits = W * H * 3 * lsb
        if len(payload) * 8 > max_bits:
            cap_bytes = max_bits // 8
            messagebox.showerror("Too big",
                f"Payload too large for this image.\nPayload: {len(payload)} bytes, Capacity: {cap_bytes} bytes with {lsb} LSB(s).\n\n"
                "Solutions:\n"
                "- Enable compression (tick 'Compress payload')\n"
                "- Increase LSB depth to 2 or 3 (more capacity, more visible changes)\n"
                "- Use a larger cover image (open a larger image)\n"
                "- Choose a smaller secret payload (e.g. reduce image/audio quality)")
            return

        # UI busy
        self._set_busy(True)
        self.status_var.set("Encoding...")
        self.progress["value"] = 8

        try:
            stego = embed_payload_in_image(self.original_image.copy(), payload, lsb=lsb)
            self.stego_image = stego
            self.show_preview(stego)
            self.save_btn.configure(state="normal")
            self.progress["value"] = 100
            self.status_var.set("Encoding complete. Save the stego image.")
            # clear password after successful encode
            self.pw_var.set("")
            messagebox.showinfo("Success", "Secret embedded in memory. Use 'Save Stego' to write a file (PNG recommended).")
        except Exception as e:
            messagebox.showerror("Encoding failed", f"{e}")
            self.status_var.set("Error")
        finally:
            self._set_busy(False)
            self.progress["value"] = 0

    def save_stego(self):
        if self.stego_image is None:
            messagebox.showwarning("No stego", "No stego image to save. Encode first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".png",
                                            filetypes=[("PNG image", "*.png"),
                                                       ("JPEG image", ".jpg;*.jpeg"),
                                                       ("BMP image", "*.bmp")],
                                            title="Save stego image (PNG recommended)")
        if not path:
            return
        try:
            if os.path.splitext(path)[1].lower() in (".jpg", ".jpeg"):
                if not messagebox.askyesno("Warning", "Saving as JPEG will recompress and likely destroy hidden data. Continue?"):
                    return
            self.stego_image.save(path)
            messagebox.showinfo("Saved", f"Saved stego image to:\n{path}")
            self.status_var.set(f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Save error", f"Could not save image:\n{e}")

    def threaded_decode(self):
        threading.Thread(target=self.decode_action, daemon=True).start()

    def decode_action(self):
        if not self.original_image and not self.stego_image:
            messagebox.showwarning("No image", "Please select the stego image (Open Image) to decode.")
            return
        try:
            img = (self.stego_image or self.original_image).copy().convert("RGB")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open image:\n{e}")
            return

        lsb = int(self.lsb_var.get())
        self._set_busy(True)
        self.status_var.set("Decoding...")
        self.progress["value"] = 20

        try:
            blob = extract_payload_from_image(img, lsb=lsb)
            self.progress["value"] = 60
            password = self.pw_var.get().strip() or None
            kind, data = parse_payload(blob, password=password)
            if kind == 0:
                # text
                text = data.decode("utf-8", errors="replace")
                self.text_box.delete("1.0", END)
                self.text_box.insert(END, text)
                messagebox.showinfo("Decoded", "Text message extracted and placed in the text box.")
            elif kind == 1:
                # extracted image
                from io import BytesIO
                try:
                    hidden_img = Image.open(BytesIO(data)).convert("RGB")
                    # show hidden image in preview area temporarily and offer save
                    self.show_preview(hidden_img)
                    save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                             filetypes=[("PNG image", "*.png"),
                                                                        ("JPEG image", ".jpg;*.jpeg"),
                                                                        ("BMP image", "*.bmp")],
                                                             title="Save extracted hidden image (optional)")
                    if save_path:
                        hidden_img.save(save_path)
                        messagebox.showinfo("Saved", f"Hidden image saved to:\n{save_path}")
                except Exception:
                    # fallback: raw bytes
                    save_path = filedialog.asksaveasfilename(defaultextension=".bin",
                                                             filetypes=[("Binary file", "*.bin")],
                                                             title="Save extracted hidden data")
                    if save_path:
                        with open(save_path, "wb") as f:
                            f.write(data)
                        messagebox.showinfo("Saved", f"Hidden data saved to:\n{save_path}")
            elif kind == 2:
                # extracted audio
                save_path = filedialog.asksaveasfilename(defaultextension=".wav",
                                                         filetypes=[("WAV", "*.wav"), ("MP3", "*.mp3"), ("All files", "*.*")],
                                                         title="Save extracted audio")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(data)
                    messagebox.showinfo("Saved", f"Hidden audio saved to:\n{save_path}")
            else:
                messagebox.showwarning("Unknown payload", f"Decoded unknown payload kind: {kind}. Saved as raw bytes.")
                save_path = filedialog.asksaveasfilename(defaultextension=".bin",
                                                         filetypes=[("Binary file", "*.bin")],
                                                         title="Save extracted unknown payload")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(data)
                    messagebox.showinfo("Saved", f"Data saved to:\n{save_path}")

            # clear password after successful decode
            self.pw_var.set("")
            self.status_var.set("Decoding complete.")
            self.progress["value"] = 100
        except Exception as e:
            messagebox.showerror("Decode failed", f"Decoding error:\n{e}")
            self.status_var.set("Error during decoding.")
        finally:
            self._set_busy(False)
            self.progress["value"] = 0

    # -------------------------
    # UI helpers
    # -------------------------
    def _set_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.open_btn.configure(state=state)
        self.encode_btn.configure(state=state)
        self.decode_btn.configure(state=state)
        self.save_btn.configure(state=("normal" if (self.stego_image is not None and not busy) else "disabled"))
        # load button enabled only if payload kind != text and not busy
        self.load_file_btn.configure(state=("disabled" if busy else ("normal" if self.kind_var.get() != 0 else "disabled")))
        # update capacity label if an image is loaded
        if self.original_image:
            self.update_capacity_label(self.original_image)

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    root = Tk()
    app = StegApp(root)
    root.mainloop()
