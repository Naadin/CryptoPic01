# CryptoPic01

# 1. Зависимости. Команды запуска

Python 3.10+

```python
cd src
# установка зависимостей
pip install pillow numpy matplotlib pycryptodome
# запуск
python main.py
```

# 2. Параметры

```
KEY1 = "pixels"  # первый ключ для шифрования
KEY2 = "pixelс"  # ключ, в котором изменен один символ
```

# 3. Пример шифрования

```python
import os
from pathlib import Path
from main import load_pixels, save_pixels, ctr_encrypt

pix = load_pixels(Path("imgs/dots.png"))
nonce = os.urandom(8)
# шифрование
encrypted_bytes = ctr_encrypt(pix.tobytes(), key="pixels", nonce=nonce)

save_pixels(encrypted_bytes, pix.shape, Path("results/dots/ctr_sh.png"))
```

# 4. Пример расшифровывания

```python
import json
from pathlib import Path
from main import load_pixels, save_pixels, ctr_decrypt

meta = json.loads(Path("results/dots/meta.json").read_text(encoding="utf-8"))
nonce = bytes.fromhex(meta["nonce_hex"])

enc_pix = load_pixels(Path("results/dots/ctr_sh.png"))
# расшифровывание
decrypted_bytes = ctr_decrypt(enc_pix.tobytes(), key="pixels", nonce=nonce)

save_pixels(decrypted_bytes, tuple(meta["shape"]), Path("results/dots/ctr_dec.png"))
```

# 5. Какие алгоритмы реализованы

1. **Потоковое шифрование (`XOR`)** — генерация псевдослучайной ключевой последовательности на основе `xorshift32`.
2. **AES-256-ECB** — блочное шифрование, ключ длиной 256 бит формируется как `SHA-256(key)`.
3. **AES-256-CTR** — блочное шифрование со случайным 8-байтовым `nonce` (сохраняется в `meta.json` для последующего расшифрования).
