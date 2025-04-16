from fastapi import FastAPI, Request, File, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from pathlib import Path
from PIL import Image
import numpy as np
import os
import struct
import base64
import zlib
import io

app = FastAPI()

# Configure paths
BASE_DIR = Path(__file__).resolve().parent

# Mount static files and templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Constants
SALT_SIZE = 16
NUM_ITERATIONS = 100000
KEY_SIZE = 32
IV_SIZE = 16
NUM_LAYERS = 7
BITS_PER_PIXEL = 3  # For RGB images
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB

def bytes_to_binary(data):
    return ''.join(format(byte, '08b') for byte in data)

def binary_to_bytes(binary):
    return bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))

def calculate_capacity(image):
    width, height = image.size
    return (width * height * BITS_PER_PIXEL) // 8

def embed_lsb(host_image, data):
    """Efficiently embed data into an image using LSB steganography."""
    img_array = np.array(host_image).copy()

    if img_array.ndim != 3 or img_array.shape[2] < BITS_PER_PIXEL:
        raise ValueError("Image must have at least 3 channels (RGB)")

    # Flatten image for faster access
    flat_image = img_array[:, :, :BITS_PER_PIXEL].flatten()

    # Prepare binary data with length header
    data_len = len(data).to_bytes(4, 'big')
    binary_data = bytes_to_binary(data_len + data)
    num_bits = len(binary_data)

    if num_bits > len(flat_image):
        raise ValueError("Image too small to hide data")

    # Convert to array of ints (0 or 1) and update LSBs
    binary_bits = np.array(list(binary_data), dtype=np.uint8)
    flat_image[:num_bits] &= 0b11111110  # Clear LSB
    flat_image[:num_bits] |= binary_bits  # Set new LSB

    # Reshape and replace into image
    img_array[:, :, :BITS_PER_PIXEL] = flat_image.reshape(img_array.shape[0], img_array.shape[1], BITS_PER_PIXEL)
    return Image.fromarray(img_array)



def extract_lsb(image):
    img_array = np.array(image)
    height, width, channels = img_array.shape
    binary_data = []

    # Extract first 32 bits (4 bytes) for data length
    data_len_bits = []
    bits_collected = 0
    for row in range(height):
        for col in range(width):
            for ch in range(BITS_PER_PIXEL):
                if bits_collected >= 32:
                    break
                if ch >= channels:
                    continue
                data_len_bits.append(str(img_array[row, col, ch] & 1))
                bits_collected += 1
            if bits_collected >= 32:
                break
        if bits_collected >= 32:
            break

    data_len = int(''.join(data_len_bits), 2)

    # Extract full (length header + data) bits
    total_bits_needed = (data_len + 4) * 8
    bits_collected = 0
    binary_data = []
    for row in range(height):
        for col in range(width):
            for ch in range(BITS_PER_PIXEL):
                if bits_collected >= total_bits_needed:
                    break
                if ch >= channels:
                    continue
                binary_data.append(str(img_array[row, col, ch] & 1))
                bits_collected += 1
            if bits_collected >= total_bits_needed:
                break
        if bits_collected >= total_bits_needed:
            break

    full_data = binary_to_bytes(''.join(binary_data))
    return full_data[4:4+data_len]  # correct slicing now


def encrypt_data(data, public_key_data):
    public_key = RSA.import_key(public_key_data)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    session_key = get_random_bytes(16)
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)
    
    # Encrypt with AES in reverse order for layered decryption
    encrypted = zlib.compress(data)
    for _ in range(NUM_LAYERS):
        iv = get_random_bytes(IV_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(encrypted, AES.block_size))
        encrypted = iv + encrypted
    
    # Combine components
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key + salt + encrypted

def decrypt_data(encrypted_data, private_key_data, passphrase):
    private_key = RSA.import_key(private_key_data, passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    # Split components
    key_size = private_key.size_in_bytes()
    enc_session_key = encrypted_data[:key_size]
    salt = encrypted_data[key_size:key_size+SALT_SIZE]
    data = encrypted_data[key_size+SALT_SIZE:]
    
    # Derive key
    session_key = cipher_rsa.decrypt(enc_session_key)
    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)
    
    # Decrypt layers
    for _ in range(NUM_LAYERS):
        iv = data[:IV_SIZE]
        data = data[IV_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = unpad(cipher.decrypt(data), AES.block_size)
    
    return zlib.decompress(data)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/hide", response_class=HTMLResponse)
async def hide_page(request: Request):
    return templates.TemplateResponse("hide.html", {"request": request})

@app.post("/hide/")
async def hide_file(
    host_file: UploadFile = File(...),
    hidden_file: UploadFile = File(...),
    public_key: UploadFile = File(...),
):
    try:
        # Read and validate files
        host_image = Image.open(io.BytesIO(await host_file.read()))
        if host_image.mode not in ['RGB', 'RGBA']:
            raise ValueError("Only RGB/RGBA images supported")

        # Validate image format (allow PNG and BMP only)
        if host_image.format not in ["PNG", "BMP"]:
            raise ValueError("Only PNG or BMP formats supported as container images.")

        hidden_filename = hidden_file.filename.encode()
        if len(hidden_filename) > 255:
            raise ValueError("Filename too long (max 255 bytes).")
        hidden_data = await hidden_file.read()
        public_key_data = await public_key.read()

        # Include filename in encrypted data
        combined_data = struct.pack("B", len(hidden_filename)) + hidden_filename + hidden_data
        encrypted_data = encrypt_data(combined_data, public_key_data)

        # Check capacity
        capacity = calculate_capacity(host_image)
        if len(encrypted_data) > capacity:
            raise ValueError(f"Image too small. Needs {len(encrypted_data)} bytes, has {capacity}")

        # Embed data using LSB
        stego_image = embed_lsb(host_image, encrypted_data)

        # Save to buffer
        buffer = io.BytesIO()
        format_used = "BMP" if host_image.format == "BMP" else "PNG"
        stego_image.save(buffer, format=format_used)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="image/png" if format_used == "PNG" else "image/bmp",
            headers={"Content-Disposition": f"attachment; filename=stego_{host_file.filename}"}
        )

    except Exception as e:
        raise HTTPException(500, detail=f"Error: {str(e)}")

@app.get("/unhide", response_class=HTMLResponse)
async def unhide_page(request: Request):
    return templates.TemplateResponse("unhide.html", {"request": request})

@app.post("/unhide/")
async def unhide_file(
    stego_image: UploadFile = File(...),
    private_key: UploadFile = File(...),
    passphrase: str = Form(default="")
):
    try:
        image_data = await stego_image.read()
        private_key_data = await private_key.read()

        image = Image.open(io.BytesIO(image_data))
        if image.mode not in ['RGB', 'RGBA']:
            raise ValueError("Only RGB/RGBA images supported")

        encrypted_data = extract_lsb(image)
        decrypted_data = decrypt_data(encrypted_data, private_key_data, passphrase)

        # Recover original filename
        name_len = decrypted_data[0]
        filename = decrypted_data[1:1+name_len].decode()
        file_content = decrypted_data[1+name_len:]

        return StreamingResponse(io.BytesIO(file_content),
                                 media_type="application/octet-stream",
                                 headers={"Content-Disposition": f"attachment; filename={filename}"})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
 
@app.post("/generate-keypair/")
async def generate_keypair(passphrase: str = Form(default='')):
    try:
        key = RSA.generate(2048)
        private_key = key.export_key(
            passphrase=passphrase if passphrase else None,
            pkcs=8,
            protection="scryptAndAES128-CBC"
        )
        public_key = key.publickey().export_key()
        return {
            "private_key": private_key.decode('utf-8'),
            "public_key": public_key.decode('utf-8')
        }
    except Exception as e:
        raise HTTPException(500, detail=f"Key generation failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)