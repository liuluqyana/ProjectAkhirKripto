"""Verifikasi wajah DEMO lokal dengan OpenCV (bukan sistem biometrik produksi).

Template wajah disimpan terenkripsi pada DB; tidak menyimpan foto mentah.
Sistem ini rentan spoofing foto/video dan harus dipakai bersama dongle.
"""
import base64
import io
import json
import secrets

import cv2
import numpy as np

CASCADE = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
SIZE = (96, 96)
# Nilai empiris awal; wajib kalibrasi dengan pengguna/perangkat sebenarnya.
MAX_DISTANCE = 0.45


class FaceError(ValueError):
    pass


def descriptor(data_url: str):
    if not isinstance(data_url, str) or not data_url.startswith('data:image/jpeg;base64,'):
        raise FaceError('Format gambar webcam harus JPEG.')
    try:
        encoded = data_url.split(',', 1)[1]
        if len(encoded) > 1_500_000:
            raise FaceError('Ukuran frame terlalu besar.')
        data = base64.b64decode(encoded, validate=True)
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_GRAYSCALE)
    except (ValueError, TypeError) as exc:
        raise FaceError('Frame webcam tidak valid.') from exc
    if img is None or min(img.shape[:2]) < 160:
        raise FaceError('Kamera belum menghasilkan gambar yang cukup jelas.')
    faces = CASCADE.detectMultiScale(img, scaleFactor=1.1, minNeighbors=3, minSize=(75, 75))
    if len(faces) != 1:
        raise FaceError('Pastikan tepat satu wajah tampak jelas di depan kamera.')
    x, y, w, h = faces[0]
    crop = cv2.resize(img[y:y+h, x:x+w], SIZE)
    crop = cv2.equalizeHist(crop)
    # Uniform local binary patterns histogram pada 4x4 region, tahan variasi cahaya terbatas.
    c = crop[1:-1, 1:-1]
    code = np.zeros(c.shape, dtype=np.uint8)
    for i, (dy, dx) in enumerate([(-1,-1),(-1,0),(-1,1),(0,1),(1,1),(1,0),(1,-1),(0,-1)]):
        neighbour = crop[1+dy:crop.shape[0]-1+dy, 1+dx:crop.shape[1]-1+dx]
        code |= ((neighbour >= c).astype(np.uint8) << i)
    features = []
    for patch in np.array_split(code, 4, axis=0):
        for block in np.array_split(patch, 4, axis=1):
            hist = cv2.calcHist([block], [0], None, [32], [0,256]).flatten()
            hist /= max(float(hist.sum()), 1)
            features.extend(hist.tolist())
    vector = np.array(features, dtype=np.float32)
    vector /= max(float(np.linalg.norm(vector)), 1e-7)
    return vector


def enroll(frames):
    if not isinstance(frames, list) or len(frames) != 5:
        raise FaceError('Pendaftaran membutuhkan tepat 5 frame webcam.')
    vecs = [descriptor(frame) for frame in frames]
    matrix = np.stack(vecs)
    # Hindari beberapa foto yang jelas tidak konsisten.
    if float(np.max(np.linalg.norm(matrix - matrix.mean(axis=0), axis=1))) > 0.65:
        raise FaceError('Wajah antar-frame tidak konsisten. Ulangi pendaftaran.')
    return json.dumps({'version': 1, 'samples': [v.tolist() for v in vecs]})


def verify(template: str, frame: str):
    try:
        data = json.loads(template)
        if data.get('version') != 1 or len(data['samples']) != 5:
            raise ValueError('wrong template')
        refs = np.array(data['samples'], dtype=np.float32)
        if refs.shape != (5, 512):
            raise ValueError('wrong shape')
    except (ValueError, KeyError, TypeError) as exc:
        raise FaceError('Template wajah rusak.') from exc
    probe = descriptor(frame)
    distances = np.linalg.norm(refs - probe, axis=1)
    return bool(np.median(distances) <= MAX_DISTANCE)
