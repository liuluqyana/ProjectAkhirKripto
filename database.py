         pkg["available_from"], pkg["block_index"]),
    )


def _package_dict(row) -> dict:
    return {
        "id": row["id"],
        "exam_name": dec(row["exam_name_enc"], "packages.exam_name"),
        "original_name": dec(row["original_name_enc"], "packages.original_name"),
        "encrypted_sha256": row["encrypted_sha256"],
        "stego_sha256": row["stego_sha256"],
        "enc_path": row["enc_path"],
        "stego_path": row["stego_path"],
        "released_by": row["username"],
        "released_at": row["released_at"],
        "available_from": row["available_from"],
        "block_index": row["block_index"],
        "available": row["available_from"] <= utcnow_iso(),
    }


_PKG_SELECT = "SELECT p.*, u.username FROM packages p JOIN users u ON u.id = p.released_by"


def list_packages(db) -> list[dict]:
    return [_package_dict(r) for r in db.execute(_PKG_SELECT + " ORDER BY p.released_at DESC").fetchall()]


def get_package(db, package_id):
    row = db.execute(_PKG_SELECT + " WHERE p.id = ?", (package_id,)).fetchone()
    return _package_dict(row) if row else None


# --------------------------------- Logs --------------------------------------
def add_log(db, user_id, action: str, detail: str = "") -> None:
    db.execute(
        "INSERT INTO supervisor_logs(user_id, action_enc, detail_enc, created_at) VALUES (?,?,?,?)",
        (user_id, enc(action, "supervisor_logs.action"), enc(detail, "supervisor_logs.detail"), utcnow_iso()),
    )


def list_logs(db, user_id=None, limit=100) -> list[dict]:
    sql = ("SELECT l.id, l.action_enc, l.detail_enc, l.created_at, u.username, u.role "
           "FROM supervisor_logs l JOIN users u ON u.id = l.user_id")
    params: list = []
    if user_id is not None:
        sql += " WHERE l.user_id = ?"
        params.append(user_id)
    sql += " ORDER BY l.id DESC LIMIT ?"
    params.append(limit)
    return [
        {"id": r["id"], "username": r["username"], "role": r["role"], "created_at": r["created_at"],
         "action": dec(r["action_enc"], "supervisor_logs.action"),
         "detail": dec(r["detail_enc"], "supervisor_logs.detail")}
        for r in db.execute(sql, params).fetchall()
    ]


# ---------------------------- Berita acara -----------------------------------
def add_berita_acara(db, package_id, supervisor_id, content: dict) -> None:
    db.execute(
        "INSERT INTO berita_acara(package_id, supervisor_id, content_enc, created_at) VALUES (?,?,?,?)",
        (package_id, supervisor_id, enc(json.dumps(content, ensure_ascii=False), "berita_acara.content"),
         utcnow_iso()),
    )


def list_berita_acara(db, supervisor_id=None, limit=100) -> list[dict]:
    sql = ("SELECT b.id, b.package_id, b.content_enc, b.created_at, u.username, p.exam_name_enc "
           "FROM berita_acara b JOIN users u ON u.id = b.supervisor_id "
           "JOIN packages p ON p.id = b.package_id")
    params: list = []
    if supervisor_id is not None:
        sql += " WHERE b.supervisor_id = ?"
        params.append(supervisor_id)
    sql += " ORDER BY b.id DESC LIMIT ?"
    params.append(limit)
    result = []
    for r in db.execute(sql, params).fetchall():
        try:
            content = json.loads(dec(r["content_enc"], "berita_acara.content"))
        except ValueError:
            content = {}
        result.append({
            "id": r["id"], "package_id": r["package_id"], "username": r["username"],
            "created_at": r["created_at"], "exam_name": dec(r["exam_name_enc"], "packages.exam_name"),
            "ruangan": content.get("ruangan", ""), "hadir": content.get("hadir", 0),
            "tidak_hadir": content.get("tidak_hadir", 0), "catatan": content.get("catatan", ""),
        })
    return result


# ----------------------------- Kunci jawaban ----------------------------------
def save_answer_key(db, title: str, ciphertext: str, user_id: int) -> int:
    cur = db.execute(
        "INSERT INTO answer_keys(title_enc, cipher_enc, created_by, created_at) VALUES (?,?,?,?)",
        (enc(title, "answer_keys.title"), enc(ciphertext, "answer_keys.cipher"), user_id, utcnow_iso()),
    )
    return cur.lastrowid


def list_answer_keys(db) -> list[dict]:
    rows = db.execute("SELECT id, title_enc, created_at FROM answer_keys ORDER BY id DESC").fetchall()
    return [{"id": r["id"], "title": dec(r["title_enc"], "answer_keys.title"), "created_at": r["created_at"]}
            for r in rows]


def get_answer_key(db, key_id):
    r = db.execute("SELECT id, title_enc, cipher_enc FROM answer_keys WHERE id = ?", (key_id,)).fetchone()
    if r is None:
        return None
    return {"id": r["id"], "title": dec(r["title_enc"], "answer_keys.title"),
            "ciphertext": dec(r["cipher_enc"], "answer_keys.cipher")}

# ------------------------ Template wajah (terenkripsi) -----------------------
def get_face_template(db, user_id):
    row = db.execute('SELECT template_enc FROM face_templates WHERE user_id = ?', (user_id,)).fetchone()
    return decrypt_field(row['template_enc'], 'face_templates.template') if row else None


def save_face_template(db, user_id, template):
    db.execute('INSERT INTO face_templates(user_id,template_enc,created_at) VALUES (?,?,?) '
               'ON DUPLICATE KEY UPDATE template_enc=VALUES(template_enc), created_at=VALUES(created_at)',
               (user_id, enc(template, 'face_templates.template'), utcnow_iso()))
