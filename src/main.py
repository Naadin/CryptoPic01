import os
import json
import hashlib
import random
from pathlib import Path

import numpy as np
from PIL import Image
import matplotlib
matplotlib.use("Agg") 
import matplotlib.pyplot as plt

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ROOT = Path(__file__).resolve().parent.parent
IMGS = ROOT / "imgs" 
RES  = ROOT / "results" 
RES.mkdir(exist_ok=True)

# xorshift32

def key(key_str: str) -> int:
    h = hashlib.sha256(key_str.encode()).hexdigest()
    return int(h[:8], 16) & 0xFFFFFFFF


def xorshift32(state: int) -> int:
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= (state >> 17)
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF


def key_bytes(key_str: str, n: int) -> bytes:
    state = key(key_str)
    out = bytearray()
    while len(out) < n:
        state = xorshift32(state)
        out.extend(state.to_bytes(4, "little"))
    return bytes(out[:n])


def xor(data: bytes, key_str: str) -> bytes:
    ks = key_bytes(key_str, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))

# AES: ECB и CTR

def get_aes_key(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()


def ecb_encrypt(data: bytes, key: str) -> bytes:
    cipher = AES.new(get_aes_key(key), AES.MODE_ECB)
    return cipher.encrypt(pad(data, 16))


def ecb_decrypt(data: bytes, key: str) -> bytes:
    cipher = AES.new(get_aes_key(key), AES.MODE_ECB)
    return unpad(cipher.decrypt(data), 16)


def ctr_encrypt(data: bytes, key: str, nonce: bytes) -> bytes:
    cipher = AES.new(get_aes_key(key), AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(data)


def ctr_decrypt(data: bytes, key: str, nonce: bytes) -> bytes:
    cipher = AES.new(get_aes_key(key), AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(data)

# метрики

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256).astype(float)
    p = counts[counts > 0] / len(arr)
    return float(-(p * np.log2(p)).sum())


def load_pixels(path: Path) -> np.ndarray:
    img = Image.open(path).convert("RGB")
    return np.array(img)


def correlation(pixels: np.ndarray, direction: str, n_samples: int = 5000):
    h, w, _ = pixels.shape
    a, b = [], []
    rng = random.Random(42) 
    if direction == "h":
        for _ in range(n_samples):
            y = rng.randrange(h)
            x = rng.randrange(w - 1)
            a.append(pixels[y, x, 0])
            b.append(pixels[y, x + 1, 0])
    else: 
        for _ in range(n_samples):
            y = rng.randrange(h - 1)
            x = rng.randrange(w)
            a.append(pixels[y, x, 0])
            b.append(pixels[y + 1, x, 0])
    a = np.array(a, float)
    b = np.array(b, float)
    if a.std() == 0 or b.std() == 0:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


def bytes_to_pixels(data: bytes, shape) -> np.ndarray:
    n = shape[0] * shape[1] * shape[2]
    arr = np.frombuffer(data[:n], dtype=np.uint8)
    if len(arr) < n:
        arr = np.pad(arr, (0, n - len(arr)))
    return arr.reshape(shape)


def npcr_uaci(c1: bytes, c2: bytes):
    n = min(len(c1), len(c2))
    a = np.frombuffer(c1[:n], dtype=np.uint8).astype(int)
    b = np.frombuffer(c2[:n], dtype=np.uint8).astype(int)
    diff = a != b
    npcr = diff.mean() * 100.0
    uaci = (np.abs(a - b) / 255.0).mean() * 100.0
    return float(npcr), float(uaci)

# main

def process_image(img_name: str):
    print(f"\n=== Обработка: {img_name} ===")
    src_img = IMGS / img_name

    raw = src_img.read_bytes()

    KEY1 = "secret-key-1"
    KEY2 = "secret-key-2"

    xor_enc = xor(raw, KEY1)
    xor_dec = xor(xor_enc, KEY1)

    ecb_enc = ecb_encrypt(raw, KEY1)
    ecb_dec = ecb_decrypt(ecb_enc, KEY1)

    nonce = os.urandom(8)
    ctr_enc = ctr_encrypt(raw, KEY1, nonce)
    ctr_dec = ctr_decrypt(ctr_enc, KEY1, nonce)

    def sha(b): return hashlib.sha256(b).hexdigest()
    reversible = {
        "xor":     sha(raw) == sha(xor_dec),
        "ecb": sha(raw) == sha(ecb_dec),
        "ctr": sha(raw) == sha(ctr_dec),
    }
    print("Обратимость (True = всё оки):", reversible)

    out_dir = RES / src_img.stem
    out_dir.mkdir(exist_ok=True)

    (out_dir / "xor_dec.png").write_bytes(xor_dec)
    (out_dir / "ecb_dec.png").write_bytes(ecb_dec)
    (out_dir / "ctr_dec.png").write_bytes(ctr_dec)

    pix_orig = load_pixels(src_img)
    shape = pix_orig.shape

    raw_pixels = pix_orig.tobytes() 
    
    xor_pix_enc = xor(raw_pixels, KEY1)
    ecb_pix_enc = ecb_encrypt(raw_pixels, KEY1)
    nonce_pix = os.urandom(8)
    ctr_pix_enc = ctr_encrypt(raw_pixels, KEY1, nonce_pix)

    def save_as_image(data: bytes, shape, filename: Path):
        n = shape[0] * shape[1] * shape[2]
        arr = np.frombuffer(data[:n], dtype=np.uint8)
        if len(arr) < n:
            arr = np.pad(arr, (0, n - len(arr)))
        img_array = arr.reshape(shape)
        Image.fromarray(img_array, 'RGB').save(filename)

    save_as_image(xor_pix_enc, shape, out_dir / "xor_sh.png")
    save_as_image(ecb_pix_enc, shape, out_dir / "ecb_sh.png")
    save_as_image(ctr_pix_enc, shape, out_dir / "ctr_sh.png")

    meta = {
        "source": img_name,
        "aes_ctr_nonce_hex": nonce.hex(),
        "methods": ["xor-xorshift32", "aes-256-ecb", "aes-256-ctr"],
        "reversible": reversible,
        "sha256_before": sha(raw),
        "sha256_after_xor": sha(xor_dec),
        "sha256_after_ecb": sha(ecb_dec),
        "sha256_after_ctr": sha(ctr_dec),
    }
    (out_dir / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False)
    )

    datasets = {
        "Исходное": raw,
        "XOR":      xor_enc,
        "AES-ECB":  ecb_enc,
        "AES-CTR":  ctr_enc,
    }

    rows = []
    for name, data in datasets.items():
        ent = entropy(data)
        if name == "Исходное":
            pix = pix_orig
        else:
            pix = bytes_to_pixels(data, shape)
        ch = correlation(pix, "h")
        cv = correlation(pix, "v")
        rows.append((name, ent, ch, cv))

    with open(out_dir / "metrics.csv", "w", encoding="utf-8") as f:
        f.write("method,entropy,corr_h,corr_v\n")
        for name, ent, ch, cv in rows:
            f.write(f"{name},{ent:.6f},{ch:.6f},{cv:.6f}\n")

    print(f"{'Метод':<12}{'Энтропия':>10}{'Corr H':>10}{'Corr V':>10}")
    for name, ent, ch, cv in rows:
        print(f"{name:<12}{ent:>10.4f}{ch:>10.4f}{cv:>10.4f}")

    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    for ax, (name, data) in zip(axes.flat, datasets.items()):
        arr = np.frombuffer(data, dtype=np.uint8)
        ax.hist(arr, bins=256, range=(0, 255), color="steelblue")
        ax.set_title(f"{img_name} — {name}")
        ax.set_xlim(0, 255)
    plt.tight_layout()
    plt.savefig(out_dir / "histograms.png", dpi=120)
    plt.close()

    k2_enc = ctr_encrypt(raw, KEY2, nonce)
    npcr, uaci = npcr_uaci(ctr_enc, k2_enc)
    print(f"NPCR = {npcr:.2f}%   UACI = {uaci:.2f}%")
    (out_dir / "res.txt").write_text(
        f"NPCR={npcr:.4f}%\nUACI={uaci:.4f}%\n"
    )

def main():
    images = ["dots.png", "checkerboard.png", "gradient.png"]
    for name in images:
        process_image(name)

if __name__ == "__main__":
    main()