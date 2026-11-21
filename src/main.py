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
def derive_seed(key_str: str) -> int:
    h = hashlib.sha256(key_str.encode("utf-8")).hexdigest()
    seed = int(h[:8], 16) & 0xFFFFFFFF
    return seed if seed != 0 else 0x12345678

def xorshift32(state: int) -> int:
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= (state >> 17)
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF

def generate_keystream(key_str: str, n: int) -> bytes:
    state = derive_seed(key_str)
    out = bytearray()
    while len(out) < n:
        state = xorshift32(state)
        out.extend(state.to_bytes(4, "little"))
    return bytes(out[:n])

def xor_crypt(data: bytes, key_str: str) -> bytes:
    ks = generate_keystream(key_str, len(data))
    arr_data = np.frombuffer(data, dtype=np.uint8)
    arr_ks = np.frombuffer(ks, dtype=np.uint8)
    return np.bitwise_xor(arr_data, arr_ks).tobytes()

# AES: ECB и CTR
def get_aes_key(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()

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
    return np.array(img, dtype=np.uint8)

def save_pixels(data: bytes, shape: tuple, path: Path):
    expected_len = int(np.prod(shape))
    arr = np.frombuffer(data[:expected_len], dtype=np.uint8).reshape(shape)
    Image.fromarray(arr, mode="RGB").save(path, format="PNG")

def correlation(pixels: np.ndarray, direction: str, n_samples: int = 5000) -> float:
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
    a = np.array(a, dtype=float)
    b = np.array(b, dtype=float)
    if a.std() == 0 or b.std() == 0:
        return 0.0
    return float(np.corrcoef(a, b).item(1))

def npcr_uaci(c1: bytes, c2: bytes) -> tuple:
    n = min(len(c1), len(c2))
    a = np.frombuffer(c1[:n], dtype=np.uint8).astype(np.int32)
    b = np.frombuffer(c2[:n], dtype=np.uint8).astype(np.int32)
    npcr = float((a != b).mean() * 100.0)
    uaci = float((np.abs(a - b) / 255.0).mean() * 100.0)
    return npcr, uaci

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# main
def process_image(img_name: str, is_primary: bool = False):
    print(f"\n=== Обработка: {img_name} ===")
    src_img = IMGS / img_name
    if not src_img.exists():
        print(f"Файл {src_img} не найден")
        return

    pix_orig = load_pixels(src_img)
    shape = pix_orig.shape
    raw_pixels = pix_orig.tobytes()

    KEY1 = "pixels"
    KEY2 = "pixelс"

    out_dir = RES / src_img.stem
    out_dir.mkdir(exist_ok=True)

    xor_enc = xor_crypt(raw_pixels, KEY1)
    ecb_enc = ecb_encrypt(raw_pixels, KEY1)
    nonce = os.urandom(8)
    ctr_enc = ctr_encrypt(raw_pixels, KEY1, nonce)

    xor_sh_path = out_dir / "xor_sh.png"
    ecb_sh_path = out_dir / "ecb_sh.png"
    ctr_sh_path = out_dir / "ctr_sh.png"

    save_pixels(xor_enc, shape, xor_sh_path)
    save_pixels(ecb_enc, shape, ecb_sh_path)
    save_pixels(ctr_enc, shape, ctr_sh_path)

    meta_path = out_dir / "meta.json"
    meta = {
        "source": img_name,
        "shape": list(shape),
        "algorithm_ctr": "aes-256-ctr",
        "nonce_hex": nonce.hex(),
        "ecb_tail_hex": ecb_enc[len(raw_pixels):].hex(),
        "sha256_orig_pixels": sha256_bytes(raw_pixels),
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    loaded_meta = json.loads(meta_path.read_text(encoding="utf-8"))
    loaded_nonce = bytes.fromhex(loaded_meta["nonce_hex"])
    loaded_ecb_tail = bytes.fromhex(loaded_meta["ecb_tail_hex"])

    xor_dec = xor_crypt(load_pixels(xor_sh_path).tobytes(), KEY1)
    ecb_dec = ecb_decrypt(load_pixels(ecb_sh_path).tobytes() + loaded_ecb_tail, KEY1)
    ctr_dec = ctr_decrypt(load_pixels(ctr_sh_path).tobytes(), KEY1, loaded_nonce)

    save_pixels(xor_dec, shape, out_dir / "xor_dec.png")
    save_pixels(ecb_dec, shape, out_dir / "ecb_dec.png")
    save_pixels(ctr_dec, shape, out_dir / "ctr_dec.png")

    orig_hash = sha256_bytes(raw_pixels)
    reversible = {
        "xor": orig_hash == sha256_bytes(xor_dec),
        "ecb": orig_hash == sha256_bytes(ecb_dec),
        "ctr": orig_hash == sha256_bytes(ctr_dec),
    }
    assert all(reversible.values()), "Ошибка"

    loaded_meta["reversible"] = reversible
    loaded_meta["sha256_restored_xor"] = sha256_bytes(xor_dec)
    loaded_meta["sha256_restored_ecb"] = sha256_bytes(ecb_dec)
    loaded_meta["sha256_restored_ctr"] = sha256_bytes(ctr_dec)
    meta_path.write_text(json.dumps(loaded_meta, indent=2, ensure_ascii=False), encoding="utf-8")

    if not is_primary:
        print(f"Изображения для {img_name} сохранены в {out_dir}")
        return

    print("Обратимость восстановленных пикселей (SHA-256):", reversible)

    ecb_pix_bytes = ecb_enc[:len(raw_pixels)]
    datasets = {
        "Исходное": raw_pixels,
        "XOR":      xor_enc,
        "AES-ECB":  ecb_pix_bytes,
        "AES-CTR":  ctr_enc,
    }

    rows = []
    for name, data in datasets.items():
        ent = entropy(data)
        pix = np.frombuffer(data, dtype=np.uint8).reshape(shape)
        ch = correlation(pix, "h", n_samples=5000)
        cv = correlation(pix, "v", n_samples=5000)
        rows.append((name, ent, ch, cv))

    for target_csv in (out_dir / "metrics.csv", RES / "metrics.csv"):
        with open(target_csv, "w", encoding="utf-8") as f:
            f.write("method,entropy,corr_h,corr_v\n")
            for name, ent, ch, cv in rows:
                f.write(f"{name},{ent:.6f},{ch:.6f},{cv:.6f}\n")

    print(f"\n{'Метод':<12}{'Энтропия':>10}{'Corr H':>10}{'Corr V':>10}")
    for name, ent, ch, cv in rows:
        print(f"{name:<12}{ent:>10.4f}{ch:>10.4f}{cv:>10.4f}")

    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    for ax, (name, data) in zip(axes.flat, datasets.items()):
        arr = np.frombuffer(data, dtype=np.uint8)
        ax.hist(arr, bins=256, range=(0, 255), color="steelblue")
        ax.set_title(f"{img_name} — {name}")
        ax.set_xlabel("Яркость (0–255)")
        ax.set_ylabel("Частота")
        ax.set_xlim(0, 255)
    plt.tight_layout()
    plt.savefig(out_dir / "histograms.png", dpi=120)
    plt.savefig(RES / "histograms.png", dpi=120)
    plt.close()

    ctr_enc_k2 = ctr_encrypt(raw_pixels, KEY2, nonce)
    npcr, uaci = npcr_uaci(ctr_enc, ctr_enc_k2)
    print(f"Чувствительность к ключу (AES-CTR, KEY1 / KEY2): NPCR = {npcr:.4f}%   UACI = {uaci:.4f}%")
    (out_dir / "key.txt").write_text(
        f"Algorithm: AES-256-CTR\nKEY1: {KEY1}\nKEY2: {KEY2}\nNPCR: {npcr:.4f}%\nUACI: {uaci:.4f}%\n",
        encoding="utf-8"
    )
    (RES / "meta.json").write_bytes(meta_path.read_bytes())

def main():
    images = ["dots.png", "gradient.png", "checkerboard.png"]
    for idx, name in enumerate(images):
        process_image(name, is_primary=(idx == 0))

if __name__ == "__main__":
    main()