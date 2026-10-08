# python -m streamlit run EquipmentManagement12.py
import streamlit as st
from datetime import datetime, timedelta
import sqlite3
import pandas as pd
import os
import hashlib
import hmac
import base64

# ==========================================
# 0. ການຕັ້ງຄ່າລະບົບໄຟລ໌ ແລະ ໂລໂກ້
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CHANGED: ກຳນົດບ່ອນເກັບຂໍ້ມູນຜ່ານ environment variable DATA_DIR
# - ໃນຄອມຂອງເຈົ້າ (ບໍ່ຕັ້ງຄ່າ): ໃຊ້ໂຟນເດີປັດຈຸບັນ ເຮັດວຽກຄືເກົ່າ
# - ເທິງ Server: ຕັ້ງ DATA_DIR=/data (ຫຼື path ທີ່ມີ Disk ຖາວອນ)
DATA_DIR = os.environ.get("DATA_DIR", ".")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "equipment_db.db")
IMAGE_DIR = os.path.join(DATA_DIR, "images")
os.makedirs(IMAGE_DIR, exist_ok=True)

LOGO_FILE = os.path.join(BASE_DIR, "TKL.jpg")


def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()


def render_header_with_logo(logo_path, title_text):
    if os.path.exists(logo_path):
        try:
            bin_str = get_base64_of_bin_file(logo_path)
            header_html = f'''
                <div style="display: flex; align-items: center; gap: 20px; margin-bottom: 20px;">
                    <img src="data:image/png;base64,{bin_str}" width="80" style="object-fit: contain;">
                    <h1 style="margin: 0; font-size: 2.2rem; line-height: 1.2;">{title_text}</h1>
                </div>
            '''
            st.markdown(header_html, unsafe_allow_html=True)
        except Exception:
            st.title(f"🛡️ {title_text}")
    else:
        st.warning(f"⚠️ ບໍ່ພົບໄຟລ໌ໂລໂກ້: {logo_path}")
        st.title(f"🛡️ {title_text}")


ADMIN_ROLE = "ຜູ້ດູແລລະບົບ (Admin)"
WAREHOUSE_ROLES = ["ສາງສິນຄ້າທີ 1", "ສາງສິນຄ້າທີ 2", "ສາງສິນຄ້າທີ 3"]
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg"}


def resolve_image_path(path):
    """ຫາໄຟລ໌ຮູບໃຫ້ເຈີ ເຖິງແມ່ນ path ເກົ່າໃນຖານຂໍ້ມູນຈະເປັນ 'images/xxx.jpg' ແຕ່ຍ້າຍ Server ແລ້ວ"""
    if not path or pd.isna(path):
        return None
    if os.path.exists(path):
        return path
    alt = os.path.join(IMAGE_DIR, os.path.basename(path))
    return alt if os.path.exists(alt) else None


# ==========================================
# 1. ຟັງຊັນຈັດການຖານຂໍ້ມູນ (SQLite)
# ==========================================
# CHANGED: ທຸກການເຊື່ອມຕໍ່ໃຊ້ຟັງຊັນນີ້ ເພື່ອໃຫ້ມີ timeout 30 ວິນາທີ (ກັນ error "database is locked")
# ແລະ ເປີດ WAL mode (ອ່ານ/ຂຽນພ້ອມກັນໄດ້ດີຂຶ້ນ)
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        pass
    return conn


# ---------- ການຈັດການລະຫັດຜ່ານ ----------
# CHANGED: ໃຊ້ PBKDF2 + salt (ມາກັບ Python ບໍ່ຕ້ອງຕິດຕັ້ງເພີ່ມ)
# ບັນຊີເກົ່າທີ່ໃຊ້ SHA-256 ຍັງ login ໄດ້ ແລະ ຈະຖືກອັບເກຣດອັດຕະໂນມັດຫຼັງ login ສຳເລັດ
PBKDF2_ITERATIONS = 200_000


def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    if not stored:
        return False, False
    if stored.startswith("pbkdf2$"):
        try:
            _, iters, salt_hex, hash_hex = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
            return hmac.compare_digest(dk.hex(), hash_hex), False
        except Exception:
            return False, False
    # ແບບເກົ່າ (SHA-256 ບໍ່ມີ salt)
    legacy = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(legacy, stored), True  # (ຖືກຕ້ອງບໍ, ຕ້ອງອັບເກຣດບໍ)


def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            role TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            asset_id TEXT PRIMARY KEY,
            category TEXT,
            model_name TEXT,
            manufacture_year INTEGER,
            warranty_expiry TEXT,
            last_maintenance TEXT,
            maintenance_interval INTEGER,
            next_due_date TEXT,
            image_path TEXT,
            warehouse_owner TEXT,
            import_date TEXT,
            price REAL,
            origin TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS export_history (
            asset_id TEXT PRIMARY KEY,
            category TEXT,
            model_name TEXT,
            warehouse_owner TEXT,
            export_date TEXT,
            import_date TEXT,
            price REAL,
            origin TEXT,
            operator_name TEXT,
            operator_position TEXT,
            operator_dept TEXT,
            recipient TEXT,
            purpose TEXT,
            ref_document TEXT
        )
    ''')

    # ຕາຕະລາງ audit log ສຳລັບບັນທຶກການແກ້ໄຂ/ລົບ ເພື່ອຄວາມໂປ່ງໃສ (traceability)
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT,
            action TEXT,
            performed_by TEXT,
            performed_role TEXT,
            performed_at TEXT,
            detail TEXT
        )
    ''')

    new_columns = [
        ("inventory", "import_date", "TEXT"),
        ("inventory", "price", "REAL"),
        ("inventory", "origin", "TEXT"),
        ("inventory", "warehouse_owner", "TEXT"),
        ("export_history", "import_date", "TEXT"),
        ("export_history", "price", "REAL"),
        ("export_history", "origin", "TEXT"),
        ("export_history", "operator_name", "TEXT"),
        ("export_history", "operator_position", "TEXT"),
        ("export_history", "operator_dept", "TEXT"),
        ("export_history", "recipient", "TEXT"),
        ("export_history", "purpose", "TEXT"),
        ("export_history", "ref_document", "TEXT")
    ]
    for table, col, dtype in new_columns:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {dtype}")
        except sqlite3.OperationalError:
            pass

    role_map = {
        "ผู้ดูแลระบบ (Admin)": ADMIN_ROLE,
        "คลังสินค้า 1": "ສາງສິນຄ້າທີ 1",
        "คลังสินค้า 2": "ສາງສິນຄ້າທີ 2",
        "คลังสินค้า 3": "ສາງສິນຄ້າທີ 3"
    }
    for thai, lao in role_map.items():
        c.execute("UPDATE users SET role = ? WHERE role = ?", (lao, thai))
        c.execute("UPDATE inventory SET warehouse_owner = ? WHERE warehouse_owner = ?", (lao, thai))
        c.execute("UPDATE export_history SET warehouse_owner = ? WHERE warehouse_owner = ?", (lao, thai))

    cat_map = {
        "อาวุธปืน (Firearm)": "ອາວຸດປືນ (Firearm)",
        "ยานพาหนะ (Vehicle)": "ຍານພາຫະນະ (Vehicle)",
        "อะไหล่ (Spare Part)": "ອາໄຫຼ່ (Spare Part)"
    }
    for thai, lao in cat_map.items():
        c.execute("UPDATE inventory SET category = ? WHERE category = ?", (lao, thai))
        c.execute("UPDATE export_history SET category = ? WHERE category = ?", (lao, thai))

    # NEW: ສ້າງ Admin ຄົນທຳອິດຈາກ environment variable (ບໍ່ຕ້ອງເປີດໃຫ້ສະໝັກ Admin ຜ່ານໜ້າເວັບ)
    admin_user = os.environ.get("ADMIN_USER")
    admin_pass = os.environ.get("ADMIN_PASS")
    if admin_user and admin_pass:
        c.execute("SELECT 1 FROM users WHERE username = ?", (admin_user,))
        if not c.fetchone():
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      (admin_user, hash_password(admin_pass), ADMIN_ROLE))

    conn.commit()
    conn.close()


def register_user(username, password, role):
    # CHANGED: ກວດຝັ່ງ server ອີກຊັ້ນ - ຫ້າມສະໝັກເປັນ Admin ຜ່ານຟອມລົງທະບຽນ
    if role not in WAREHOUSE_ROLES:
        return False
    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, hash_password(password), role))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success


def check_login(username, password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    stored, role = row
    ok, needs_upgrade = verify_password(password, stored)
    if ok and needs_upgrade:
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(password), username))
        conn.commit()
    conn.close()
    return role if ok else None


def log_action(asset_id, action, username, role, detail=""):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''INSERT INTO audit_log (asset_id, action, performed_by, performed_role, performed_at, detail)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (asset_id, action, username, role, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), detail))
    conn.commit()
    conn.close()


def get_item_owner(asset_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT warehouse_owner FROM inventory WHERE asset_id = ?", (asset_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


def save_to_db(asset_id, category, model_name, manufacture_year, warranty_expiry, last_maintenance, maintenance_interval, next_due, image_path, owner, import_date, price, origin):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO inventory
        (asset_id, category, model_name, manufacture_year, warranty_expiry, last_maintenance, maintenance_interval, next_due_date, image_path, warehouse_owner, import_date, price, origin)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (asset_id, category, model_name, manufacture_year, str(warranty_expiry), str(last_maintenance), maintenance_interval, str(next_due), image_path, owner, str(import_date), price, origin))
    conn.commit()
    conn.close()


# ຮັບ requester_role/requester_username ແລະ ອະນຸຍາດສະເພາະ Admin ເທົ່ານັ້ນ
def delete_from_db(asset_id, requester_username, requester_role):
    if requester_role != ADMIN_ROLE:
        return False, "❌ ທ່ານບໍ່ມີສິດລົບຂໍ້ມູນ. ກະລຸນາຕິດຕໍ່ຜູ້ດູແລລະບົບ."

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT image_path FROM inventory WHERE asset_id = ?", (asset_id,))
    row = c.fetchone()
    img = resolve_image_path(row[0]) if row else None
    if img:
        try:
            os.remove(img)
        except OSError:
            pass
    c.execute("DELETE FROM inventory WHERE asset_id = ?", (asset_id,))
    conn.commit()
    conn.close()
    log_action(asset_id, "DELETE", requester_username, requester_role)
    return True, "🗑️ ລົບຂໍ້ມູນສຳເລັດແລ້ວ"


# ກວດສອບຄວາມເປັນເຈົ້າຂອງກ່ອນປະຕິບັດການ (ຜູ້ໃຊ້ທົ່ວໄປສົ່ງອອກໄດ້ສະເພາະສາງຕົນເອງ)
def export_item_db(asset_id, op_name, op_pos, op_dept, recipient, purpose, ref_doc, requester_username, requester_role):
    owner = get_item_owner(asset_id)
    if owner is None:
        return False, "❌ ບໍ່ພົບລາຍການນີ້ໃນຄັງ"
    if requester_role != ADMIN_ROLE and owner != requester_role:
        return False, "❌ ທ່ານບໍ່ມີສິດສົ່ງອອກລາຍການຂອງສາງອື່ນ"

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT category, model_name, warehouse_owner, import_date, price, origin FROM inventory WHERE asset_id = ?", (asset_id,))
    row = c.fetchone()
    if row:
        export_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('''INSERT OR REPLACE INTO export_history
                     (asset_id, category, model_name, warehouse_owner, export_date, import_date, price, origin,
                      operator_name, operator_position, operator_dept, recipient, purpose, ref_document)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (asset_id, row[0], row[1], row[2], export_date, row[3], row[4], row[5],
                   op_name, op_pos, op_dept, recipient, purpose, ref_doc))
        c.execute("DELETE FROM inventory WHERE asset_id = ?", (asset_id,))
        conn.commit()
    conn.close()
    log_action(asset_id, "EXPORT", requester_username, requester_role, f"recipient={recipient}, purpose={purpose}")
    return True, f"✅ ບັນທຶກປະຫວັດການສົ່ງອອກ {asset_id} ແລະ ຕັດຍອດອອກຈາກຄັງແລ້ວ!"


def load_export_history(warehouse_owner=None):
    conn = get_conn()
    if warehouse_owner:
        df = pd.read_sql_query(
            "SELECT * FROM export_history WHERE warehouse_owner = ? ORDER BY export_date DESC",
            conn, params=(warehouse_owner,)
        )
    else:
        df = pd.read_sql_query("SELECT * FROM export_history ORDER BY export_date DESC", conn)
    conn.close()
    return df


def clear_old_exports():
    conn = get_conn()
    c = conn.cursor()
    two_years_ago = (datetime.now() - timedelta(days=730)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("DELETE FROM export_history WHERE export_date < ?", (two_years_ago,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted


def load_data(role):
    conn = get_conn()
    if role == ADMIN_ROLE:
        df = pd.read_sql_query("SELECT * FROM inventory", conn)
    else:
        df = pd.read_sql_query("SELECT * FROM inventory WHERE warehouse_owner = ?", conn, params=(role,))
    conn.close()
    return df


# ---------- NEW: ຟັງຊັນຈັດການຜູ້ໃຊ້ (ສຳລັບ Admin ເທົ່ານັ້ນ) ----------
def list_users():
    conn = get_conn()
    df = pd.read_sql_query("SELECT username, role FROM users ORDER BY role, username", conn)
    conn.close()
    return df


def admin_create_user(username, password, role, actor_username, actor_role):
    if actor_role != ADMIN_ROLE:
        return False, "❌ ທ່ານບໍ່ມີສິດສ້າງບັນຊີ"
    username = (username or "").strip()
    if not username:
        return False, "❌ ກະລຸນາປ້ອນຊື່ຜູ້ໃຊ້ງານ"
    if len(password or "") < 8:
        return False, "❌ ລະຫັດຜ່ານຕ້ອງມີຢ່າງໜ້ອຍ 8 ຕົວອັກສອນ"
    if role not in WAREHOUSE_ROLES + [ADMIN_ROLE]:
        return False, "❌ ສິດບໍ່ຖືກຕ້ອງ"
    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, hash_password(password), role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False, "❌ ຊື່ຜູ້ໃຊ້ນີ້ມີຢູ່ໃນລະບົບແລ້ວ"
    conn.close()
    log_action("-", "CREATE_USER", actor_username, actor_role, f"user={username}, role={role}")
    return True, f"✅ ສ້າງບັນຊີ '{username}' ສຳເລັດແລ້ວ"


def admin_delete_user(username, actor_username, actor_role):
    if actor_role != ADMIN_ROLE:
        return False, "❌ ທ່ານບໍ່ມີສິດລົບບັນຊີ"
    if username == actor_username:
        return False, "❌ ບໍ່ສາມາດລົບບັນຊີຂອງຕົນເອງໄດ້"
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "❌ ບໍ່ພົບຜູ້ໃຊ້ນີ້"
    if row[0] == ADMIN_ROLE:
        c.execute("SELECT COUNT(*) FROM users WHERE role = ?", (ADMIN_ROLE,))
        if c.fetchone()[0] <= 1:
            conn.close()
            return False, "❌ ບໍ່ສາມາດລົບ Admin ຄົນສຸດທ້າຍໄດ້"
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    log_action("-", "DELETE_USER", actor_username, actor_role, f"user={username}, role={row[0]}")
    return True, f"🗑️ ລົບບັນຊີ '{username}' ສຳເລັດແລ້ວ"


def admin_reset_password(username, new_password, actor_username, actor_role):
    if actor_role != ADMIN_ROLE:
        return False, "❌ ທ່ານບໍ່ມີສິດປ່ຽນລະຫັດຜ່ານ"
    if len(new_password or "") < 8:
        return False, "❌ ລະຫັດຜ່ານຕ້ອງມີຢ່າງໜ້ອຍ 8 ຕົວອັກສອນ"
    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(new_password), username))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if not changed:
        return False, "❌ ບໍ່ພົບຜູ້ໃຊ້ນີ້"
    log_action("-", "RESET_PASSWORD", actor_username, actor_role, f"user={username}")
    return True, f"✅ ປ່ຽນລະຫັດຜ່ານຂອງ '{username}' ສຳເລັດແລ້ວ"


init_db()

# ==========================================
# 2. ລະບົບຢືນຢັນຕົວຕົນ (Authentication UI)
# ==========================================
st.set_page_config(page_title="ລະບົບຈັດການ ອາວຸດຍຸດໂທປະກອນ", page_icon="🛡️", layout="wide")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
if "edit_mode" not in st.session_state:
    st.session_state.edit_mode = False
    st.session_state.edit_data = {}
if "export_item_id" not in st.session_state:
    st.session_state.export_item_id = None
if "confirm_delete_id" not in st.session_state:
    st.session_state.confirm_delete_id = None

if not st.session_state.logged_in:
    render_header_with_logo(LOGO_FILE, "ສູນກາງຄວບຄຸມລະບົບຄຸ້ມຄອງອາວຸ ຍຸດໂທປະກອນຂອງກອງທັບ")

    auth_tab, reg_tab = st.tabs(["🔑 ເຂົ້າສູ່ລະບົບ (Login)", "📝 ລົງທະບຽນຜູ້ໃຊ້ໃໝ່ (Register)"])

    with auth_tab:
        st.subheader("ກະລຸນາເຂົ້າສູ່ລະບົບເພື່ອໃຊ້ງານ")
        login_user = st.text_input("ຊື່ຜູ້ໃຊ້ງານ (Username)", key="login_user")
        login_pass = st.text_input("ລະຫັດຜ່ານ (Password)", type="password", key="login_pass")
        if st.button("🔓 ເຂົ້າສູ່ລະບົບ", type="primary"):
            role = check_login(login_user, login_pass)
            if role:
                st.session_state.logged_in = True
                st.session_state.username = login_user
                st.session_state.role = role
                st.rerun()
            else:
                st.error("❌ ຊື່ຜູ້ໃຊ້ງານ ຫຼື ລະຫັດຜ່ານບໍ່ຖືກຕ້ອງ")

    with reg_tab:
        # CHANGED: ການລົງທະບຽນຕ້ອງມີ "ລະຫັດເຊີນ" (REG_CODE) ແລະ ບໍ່ມີຕົວເລືອກ Admin
        REG_CODE = os.environ.get("REG_CODE", "")
        st.subheader("📝 ສ້າງບັນຊີຜູ້ໃຊ້ງານໃໝ່")

        if not REG_CODE:
            st.info("🔒 ການລົງທະບຽນຜູ້ໃຊ້ໃໝ່ຖືກປິດຢູ່. ກະລຸນາຕິດຕໍ່ຜູ້ດູແລລະບົບເພື່ອຂໍສ້າງບັນຊີ.")
        else:
            reg_user = st.text_input("ຕັ້ງຊື່ຜູ້ໃຊ້ງານ", key="reg_user")
            reg_pass = st.text_input("ຕັ້ງລະຫັດຜ່ານ (ຢ່າງໜ້ອຍ 8 ຕົວອັກສອນ)", type="password", key="reg_pass")
            reg_role = st.selectbox("ເລືອກສາງຂອງທ່ານ", WAREHOUSE_ROLES)
            reg_code = st.text_input("ລະຫັດເຊີນ (ຂໍຈາກຜູ້ດູແລລະບົບ)", type="password", key="reg_code")

            if st.button("💾 ບັນທຶກການລົງທະບຽນ"):
                reg_user_clean = reg_user.strip()
                if not hmac.compare_digest(reg_code, REG_CODE):
                    st.error("❌ ລະຫັດເຊີນບໍ່ຖືກຕ້ອງ")
                elif not reg_user_clean:
                    st.error("❌ ກະລຸນາປ້ອນຊື່ຜູ້ໃຊ້ງານ")
                elif len(reg_pass) < 8:
                    st.error("❌ ລະຫັດຜ່ານຕ້ອງມີຢ່າງໜ້ອຍ 8 ຕົວອັກສອນ")
                elif register_user(reg_user_clean, reg_pass, reg_role):
                    st.success("ລົງທະບຽນສໍາເລັດແລ້ວ! ສະລັບໄປທີ່ແທັບເຂົ້າສູ່ລະບົບໄດ້ເລີຍ")
                else:
                    st.error("❌ ຊື່ຜູ້ໃຊ້ນີ້ມີຢູ່ໃນລະບົບແລ້ວ")
    st.stop()

# ==========================================
# 3. ສ່ວນຫຼັກຂອງແອັບພລິເຄຊັນ
# ==========================================
IS_ADMIN = st.session_state.role == ADMIN_ROLE

with st.sidebar:
    st.write(f"### 👤 {st.session_state.username}")
    st.info(f"🔰 ສິດ: {st.session_state.role}")
    if st.button("🔒 ອອກຈາກລະບົບ", type="secondary"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.role = ""
        st.session_state.edit_mode = False
        st.session_state.edit_data = {}
        st.session_state.export_item_id = None
        st.session_state.confirm_delete_id = None
        st.rerun()

render_header_with_logo(LOGO_FILE, f"ລະບົບຈັດການຄຸ້ມຄອງພາຫະນະອາວຸດ ຍຸດໂທປະກອນ ຂອງກອງທັບ - {st.session_state.role}")

col1, col2 = st.columns([1.2, 2])
CURRENT_YEAR = datetime.now().year

# ----------------- ຄໍລໍາຊ້າຍ: ຟອມຂໍ້ມູນ -----------------
with col1:
    with st.form(key="inventory_form", clear_on_submit=not st.session_state.edit_mode):
        if st.session_state.edit_mode:
            st.subheader("✏️ ແກ້ໄຂຂໍ້ມູນຂອງອາວຸດຍຸດໂທປະກອນ")
            asset_id = st.text_input("ລະຫັດປະຈໍາຕົວ", value=st.session_state.edit_data["asset_id"], disabled=True)
        else:
            st.subheader("📝 ລົງທະບຽນນໍາເຂົ້າລາຍການໃໝ່")
            asset_id = st.text_input("ລະຫັດປະຈໍາຕົວ (Serial No. / Part No.)")

        # NEW: Admin ຕ້ອງເລືອກວ່າຈະນຳເຂົ້າລາຍການໃໝ່ເຂົ້າສາງໃດ
        # (ເດີມຖືກບັນທຶກເປັນຂອງ "Admin" ເຊິ່ງບໍ່ປາກົດໃນສາງ 1/2/3 ເລີຍ)
        target_warehouse = None
        if IS_ADMIN and not st.session_state.edit_mode:
            target_warehouse = st.selectbox("🏢 ນໍາເຂົ້າສາງ", WAREHOUSE_ROLES)

        categories = ["ອາວຸດປືນ (Firearm)", "ຍານພາຫະນະ (Vehicle)", "ອາໄຫຼ່ (Spare Part)"]
        cat_idx = categories.index(st.session_state.edit_data.get("category", categories[0])) if st.session_state.edit_mode else 0
        category = st.selectbox("ໝວດໝູ່ສິນຄ້າ", categories, index=cat_idx)

        model_name = st.text_input("ຊື່ລຸ້ນ / ລາຍລະອຽດ", value=st.session_state.edit_data.get("model_name", ""))
        uploaded_image = st.file_uploader("📸 ອັບໂລດຮູບພາບໃໝ່", type=['png', 'jpg', 'jpeg'])

        st.markdown("---")
        st.caption("📦 ຂໍ້ມູນນໍາເຂົ້າ ແລະ ລາຄາ")

        def_import = datetime.strptime(st.session_state.edit_data["import_date"], "%Y-%m-%d").date() if st.session_state.edit_mode and pd.notna(st.session_state.edit_data.get("import_date")) else datetime.today().date()
        import_date = st.date_input("📅 ວັນທີນໍາເຂົ້າ", value=def_import)

        def_price = float(st.session_state.edit_data.get("price", 0.0)) if st.session_state.edit_mode and pd.notna(st.session_state.edit_data.get("price")) else 0.0
        price = st.number_input("💰 ລາຄາສິນຄ້າ (ກີບ)", min_value=0.0, value=def_price, step=100.0)

        def_origin = st.session_state.edit_data.get("origin", "") if st.session_state.edit_mode and pd.notna(st.session_state.edit_data.get("origin")) else ""
        origin = st.text_input("🌍 ນໍາເຂົ້າຈາກພາກສ່ວນ/ປະເທດ (Origin)", value=def_origin)

        st.markdown("---")
        st.caption("🔧 ຂໍ້ມູນວິສະວະກຳ ແລະ ການບໍາລຸງຮັກສາ")

        manufacture_year = st.number_input("ປີຜະລິດ (ຄ.ສ.)", min_value=1900, max_value=CURRENT_YEAR, value=int(st.session_state.edit_data.get("manufacture_year", CURRENT_YEAR)))

        def_warranty = datetime.strptime(st.session_state.edit_data["warranty_expiry"], "%Y-%m-%d").date() if st.session_state.edit_mode else datetime.today().date()
        warranty_expiry = st.date_input("ວັນສິນສຸດການຮັບປະກັນສິນຄ້າ", value=def_warranty)

        def_maint = datetime.strptime(st.session_state.edit_data["last_maintenance"], "%Y-%m-%d").date() if st.session_state.edit_mode else datetime.today().date()
        last_maintenance = st.date_input("ກວດກາສະພາບ ແລະ ບໍາລຸງຮັກສາຄັ້ງລ້າສຸດ", value=def_maint)

        intervals = [7, 30, 90, 180]
        int_idx = intervals.index(int(st.session_state.edit_data.get("maintenance_interval", 30))) if st.session_state.edit_mode else 1
        maintenance_interval = st.radio("ຮອບກວດກາສະພາບ ແລະ ບໍາລຸງຮັກສາ (ວັນ)", intervals, index=int_idx)

        submit_button = st.form_submit_button("💾 ບັນທຶກຂໍ້ມູນເຂົ້າຄັງ")

    if submit_button:
        asset_id = (asset_id or "").strip()
        model_name = (model_name or "").strip()
        existing_owner = get_item_owner(asset_id) if asset_id else None

        if not asset_id or not model_name:
            st.error("❌ ກະລຸນາປ້ອນລະຫັດ ຊື່ລຸ້ນ ແລະ ລາຍການຕ່າງໆໃຫ້ຄົບຖ້ວນ")
        elif not st.session_state.edit_mode and existing_owner is not None:
            # NEW: ກັນການນຳເຂົ້າລະຫັດຊ້ຳ ທີ່ຈະຂຽນທັບ (ແລະ ຍາດເອົາ) ລາຍການຂອງສາງອື່ນ
            st.error(f"❌ ລະຫັດນີ້ມີຢູ່ໃນຄັງແລ້ວ (ສາງ: {existing_owner}). ຖ້າຕ້ອງການແກ້ໄຂ ໃຫ້ໃຊ້ປຸ່ມ 'ແກ້ໄຂ' ໃນລາຍການ")
        elif st.session_state.edit_mode and existing_owner is None:
            st.error("❌ ບໍ່ພົບລາຍການນີ້ໃນຄັງ (ອາດຖືກສົ່ງອອກ ຫຼື ລົບແລ້ວ)")
        elif st.session_state.edit_mode and not IS_ADMIN and existing_owner != st.session_state.role:
            # CHANGED: ກວດສິດຈາກຖານຂໍ້ມູນໂດຍກົງ ບໍ່ເຊື່ອຂໍ້ມູນໃນ session
            st.error("❌ ທ່ານບໍ່ມີສິດແກ້ໄຂລາຍການຂອງສາງອື່ນ")
        else:
            saved_image_path = st.session_state.edit_data.get("image_path") if st.session_state.edit_mode else None
            if uploaded_image:
                # CHANGED: ບໍ່ໃຊ້ລະຫັດທີ່ຜູ້ໃຊ້ພິມເປັນຊື່ໄຟລ໌ໂດຍກົງ (ກັນ path ອັນຕະລາຍ ເຊັ່ນ ../../)
                file_ext = uploaded_image.name.rsplit('.', 1)[-1].lower()
                if file_ext not in ALLOWED_IMAGE_EXT:
                    file_ext = "jpg"
                safe_name = hashlib.sha256(asset_id.encode()).hexdigest()[:20]
                saved_image_path = os.path.join(IMAGE_DIR, f"{safe_name}.{file_ext}")
                with open(saved_image_path, "wb") as f:
                    f.write(uploaded_image.getbuffer())

            next_due = last_maintenance + timedelta(days=maintenance_interval)

            # ກຳນົດເຈົ້າຂອງລາຍການ:
            # - ແກ້ໄຂ: ໃຊ້ເຈົ້າຂອງເດີມຈາກຖານຂໍ້ມູນ
            # - ນຳເຂົ້າໃໝ່ (Admin): ໃຊ້ສາງທີ່ເລືອກ / (ຜູ້ໃຊ້ທົ່ວໄປ): ສາງຂອງຕົນເອງ
            if st.session_state.edit_mode:
                current_owner = existing_owner
            elif IS_ADMIN:
                current_owner = target_warehouse
            else:
                current_owner = st.session_state.role

            save_to_db(asset_id, category, model_name, manufacture_year, warranty_expiry, last_maintenance, maintenance_interval, next_due, saved_image_path, current_owner, import_date, price, origin)
            log_action(asset_id, "EDIT" if st.session_state.edit_mode else "IMPORT", st.session_state.username, st.session_state.role)

            st.success("🎉 ບັນທຶກສໍາເລັດແລ້ວ!")
            st.session_state.edit_mode = False
            st.session_state.edit_data = {}
            st.rerun()

    if st.session_state.edit_mode:
        if st.button("❌ ຍົກເລີກການແກ້ໄຂ"):
            st.session_state.edit_mode = False
            st.session_state.edit_data = {}
            st.rerun()


# ----------------- ສ່ວນຊ່ວຍຈັດໝວດໝູ່ຂໍ້ມູນ -----------------
def display_category_tabs(df, prefix_key):
    tab_all, tab_firearm, tab_vehicle, tab_parts = st.tabs(["📋 ທັງໝົດ", "🔫 ອາວຸດປືນ", "🚙 ຍານພາຫະນະ", "⚙️ ອາໄຫຼ່"])

    with tab_all: display_data(df, tab_key=f"{prefix_key}_all")
    with tab_firearm: display_data(df, "ອາວຸດປືນ (Firearm)", tab_key=f"{prefix_key}_firearm")
    with tab_vehicle: display_data(df, "ຍານພາຫະນະ (Vehicle)", tab_key=f"{prefix_key}_vehicle")
    with tab_parts: display_data(df, "ອາໄຫຼ່ (Spare Part)", tab_key=f"{prefix_key}_parts")


def display_data(df, filter_category=None, tab_key="all"):
    temp_df = df.copy()
    if filter_category:
        temp_df = temp_df[temp_df['category'] == filter_category]

    search_query = st.text_input("ຄົ້ນຫາລະຫັດ ຫຼື ຊື່...", "", key=f"search_{tab_key}")
    if search_query:
        temp_df = temp_df[temp_df['asset_id'].str.contains(search_query, case=False, na=False) | temp_df['model_name'].str.contains(search_query, case=False, na=False)]

    if temp_df.empty:
        st.info("ວ່າງເປົ່າ - ບໍ່ພົບຂໍ້ມູນໃດໆເລີຍ")
    else:
        for index, row in temp_df.iterrows():
            with st.expander(f"📦 ລະຫັດ: {row['asset_id']} | {row['model_name']} | 🏢 {row['warehouse_owner']}"):
                c1, c2 = st.columns([1, 1.5])
                with c1:
                    img_path = resolve_image_path(row['image_path'])
                    if img_path:
                        st.image(img_path, use_container_width=True)
                    else:
                        st.info("ບໍ່ມີຮູບພາບ")

                    # ຜູ້ໃຊ້ທົ່ວໄປ: ເຫັນສະເພາະ ແກ້ໄຂ ແລະ ສົ່ງອອກ (ບໍ່ມີປຸ່ມລົບ)
                    if IS_ADMIN:
                        act_col1, act_col2, act_col3 = st.columns(3)
                    else:
                        act_col1, act_col2 = st.columns(2)

                    with act_col1:
                        if st.button("✏️ ແກ້ໄຂ", key=f"edit_{tab_key}_{row['asset_id']}"):
                            st.session_state.edit_mode = True
                            st.session_state.edit_data = row.to_dict()
                            st.rerun()
                    with act_col2:
                        if st.button("📤  ສົ່ງອອກ", key=f"exp_{tab_key}_{row['asset_id']}"):
                            st.session_state.export_item_id = row['asset_id']
                            st.rerun()
                    if IS_ADMIN:
                        with act_col3:
                            if st.session_state.confirm_delete_id == row['asset_id']:
                                st.warning("ຢືນຢັນການລົບ?")
                                cc1, cc2 = st.columns(2)
                                with cc1:
                                    if st.button("✅ ແມ່ນ", key=f"confirmdel_{tab_key}_{row['asset_id']}"):
                                        ok, msg = delete_from_db(row['asset_id'], st.session_state.username, st.session_state.role)
                                        st.session_state.confirm_delete_id = None
                                        st.success(msg) if ok else st.error(msg)
                                        st.rerun()
                                with cc2:
                                    if st.button("✖ ບໍ່", key=f"canceldel_{tab_key}_{row['asset_id']}"):
                                        st.session_state.confirm_delete_id = None
                                        st.rerun()
                            else:
                                if st.button("🗑️ ລົບ", key=f"del_{tab_key}_{row['asset_id']}"):
                                    st.session_state.confirm_delete_id = row['asset_id']
                                    st.rerun()

                with c2:
                    st.write(f"**ໝວດໝູ່:** {row['category']}")
                    st.write(f"**📅 ວັນທີ່ນໍາເຂົ້າ:** {row.get('import_date', '-')}")
                    price_val = row.get('price', 0.0)
                    price_val = 0.0 if pd.isna(price_val) else price_val
                    st.write(f"**💰 ລາຄາ:** {price_val:,.2f}")
                    st.write(f"**🌍 ນໍາເຂົ້າຈາກ:** {row.get('origin', '-')}")
                    st.write("---")
                    st.write(f"**ກວດກາສະພາບ ແລະ ບໍາລຸງຮັກສາຄັ້ງລ້າສຸດ:** {row['last_maintenance']}")
                    st.write(f"**ຮອບກວດກາສະພາບໃນຄັ້ງຕໍ່ໄປ:** {row['next_due_date']}")

                if st.session_state.export_item_id == row['asset_id']:
                    st.markdown("---")
                    st.markdown("#### 📝 ບັນທຶກລາຍລະອຽດການເບີກຈ່າຍ/ສົ່ງອອກ (Traceability)")
                    with st.form(key=f"form_export_trace_{tab_key}_{row['asset_id']}"):
                        st.caption("ຂໍ້ມູນຜູ້ເຮັດລາຍການ ຫຼື ຜູ້ອະນຸມັດ")
                        c_op1, c_op2, c_op3 = st.columns(3)
                        with c_op1: op_name = st.text_input("👤 ຊື່-ນາມສະກຸນ")
                        with c_op2: op_pos = st.text_input("💼 ຕຳແໜ່ງ")
                        with c_op3: op_dept = st.text_input("🏢 ສັງກັດ/ພາກສ່ວນ")

                        st.caption("ຂໍ້ມູນປາຍທາງ ແລະ ຈຸດປະສົງ")
                        c_rec1, c_rec2 = st.columns(2)
                        with c_rec1: recipient = st.text_input("🎯 ຜູ້ຮັບ/ໜ່ວຍງານປາຍທາງ")
                        with c_rec2: purpose = st.text_input("📌 ຈຸດປະສົງ (ເຊັ່ນ: ຈ່າຍຊ່ອມບໍາລຸງ, ຈຳໜ່າຍ)")

                        ref_doc = st.text_input("📄 ເລກອ້າງອີງເອກະສານ (ຖ້າມີ)")

                        submit_exp = st.form_submit_button("✅ ຢືນຢັນການເບີກຈ່າຍ")

                        if submit_exp:
                            if not op_name or not recipient or not purpose:
                                st.error("❌ ກະລຸນາປ້ອນ ຊື່ຜູ້ເຮັດລາຍການ, ຜູ້ຮັບ ແລະ ຈຸດປະສົງໃຫ້ຄົບຖ້ວນ!")
                            else:
                                ok, msg = export_item_db(
                                    row['asset_id'], op_name, op_pos, op_dept, recipient, purpose, ref_doc,
                                    st.session_state.username, st.session_state.role
                                )
                                if ok:
                                    st.session_state.export_item_id = None
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)

                    if st.button("❌ ຍົກເລີກ", key=f"cancel_exp_{tab_key}_{row['asset_id']}"):
                        st.session_state.export_item_id = None
                        st.rerun()


# ----------------- ຄໍລໍາຂວາ: ຄົ້ນຫາ ສະແດງຜົນ ແລະ ປະຫວັດ -----------------
with col2:
    if IS_ADMIN:
        st.subheader("🖥️ ສ່ວນຄວບຄຸມຂອງຜູ້ດູແລລະບົບ")
        view_mode = st.radio("ເລືອກສາງສິນຄ້າທີ່ຕ້ອງການກວດສອບ:", WAREHOUSE_ROLES + ["📜 ປະຫວັດສົ່ງອອກທັງໝົດ", "👥 ຈັດການຜູ້ໃຊ້"], horizontal=True)

        if view_mode == "👥 ຈັດການຜູ້ໃຊ້":
            st.write("### 👥 ຈັດການຜູ້ໃຊ້ງານ")

            flash = st.session_state.pop("user_flash", None)
            if flash:
                st.success(flash)

            # ----- ເພີ່ມຜູ້ໃຊ້ໃໝ່ -----
            st.write("#### ➕ ເພີ່ມຜູ້ໃຊ້ໃໝ່")
            with st.form("admin_add_user_form", clear_on_submit=True):
                nu_name = st.text_input("ຊື່ຜູ້ໃຊ້ງານ")
                nu_pass = st.text_input("ລະຫັດຜ່ານເບື້ອງຕົ້ນ (ຢ່າງໜ້ອຍ 8 ຕົວອັກສອນ)", type="password")
                nu_role = st.selectbox("ສິດ / ສາງ", WAREHOUSE_ROLES + [ADMIN_ROLE])
                if st.form_submit_button("💾 ສ້າງບັນຊີ"):
                    ok, msg = admin_create_user(nu_name, nu_pass, nu_role, st.session_state.username, st.session_state.role)
                    (st.success if ok else st.error)(msg)

            # ----- ລາຍຊື່ຜູ້ໃຊ້ -----
            st.write("#### 📋 ລາຍຊື່ຜູ້ໃຊ້ງານ")
            users_df = list_users()
            st.dataframe(users_df, use_container_width=True)

            # ----- ຕັ້ງລະຫັດຜ່ານໃໝ່ -----
            st.write("#### 🔑 ຕັ້ງລະຫັດຜ່ານໃໝ່ (ກໍລະນີລືມລະຫັດ)")
            with st.form("admin_reset_pw_form", clear_on_submit=True):
                rp_user = st.selectbox("ເລືອກຜູ້ໃຊ້", list(users_df["username"]))
                rp_pass = st.text_input("ລະຫັດຜ່ານໃໝ່ (ຢ່າງໜ້ອຍ 8 ຕົວອັກສອນ)", type="password")
                if st.form_submit_button("💾 ບັນທຶກລະຫັດຜ່ານໃໝ່"):
                    ok, msg = admin_reset_password(rp_user, rp_pass, st.session_state.username, st.session_state.role)
                    (st.success if ok else st.error)(msg)

            # ----- ລົບຜູ້ໃຊ້ -----
            st.write("#### 🗑️ ລົບຜູ້ໃຊ້")
            other_users = [u for u in users_df["username"] if u != st.session_state.username]
            if other_users:
                del_user = st.selectbox("ເລືອກຜູ້ໃຊ້ທີ່ຕ້ອງການລົບ", other_users, key="del_user_select")
                confirm_del = st.checkbox(f"ຂ້ອຍຢືນຢັນວ່າຕ້ອງການລົບບັນຊີ '{del_user}'", key=f"confirm_del_user_{del_user}")
                if st.button("🗑️ ລົບບັນຊີ", disabled=not confirm_del):
                    ok, msg = admin_delete_user(del_user, st.session_state.username, st.session_state.role)
                    if ok:
                        st.session_state.user_flash = msg
                        st.rerun()
                    else:
                        st.error(msg)
            else:
                st.info("ບໍ່ມີຜູ້ໃຊ້ອື່ນໃຫ້ລົບ")

        elif view_mode == "📜 ປະຫວັດສົ່ງອອກທັງໝົດ":
            st.write("### 📜 ປະຫວັດການເບີກຈ່າຍ / ສົ່ງອອກສິນຄ້າ (Traceability)")
            df_hist = load_export_history()
            if not df_hist.empty:
                st.dataframe(df_hist, use_container_width=True)
                if st.button("⚠️ ລົບປະຫວັດທີ່ເກົ່າ 2 ປີ", type="primary"):
                    deleted = clear_old_exports()
                    st.success(f"ທໍາຄວາມສະອາດຖານຂໍ້ມູນສໍາເລັດ! ລົບລາຍການເກົ່າໄປ {deleted} ລາຍການ")
                    st.rerun()
            else:
                st.info("ຍັງບໍ່ມີຂໍ້ມູນການສົ່ງອອກໃນລະບົບ")
        else:
            df_admin = load_data(view_mode)
            display_category_tabs(df_admin, prefix_key=f"admin_{view_mode}")

    else:
        st.subheader(f"ສາງສິນຄ້າຂອງເຈົ້າ: {st.session_state.role}")

        # ໃຫ້ຜູ້ໃຊ້ທົ່ວໄປສະຫຼັບລະຫວ່າງ "ຄັງສິນຄ້າ" ແລະ "ປະຫວັດເບີກຈ່າຍຂອງສາງຕົນເອງ"
        user_view = st.radio(
            "ເລືອກມຸມມອງ:",
            ["📦 ຄັງສິນຄ້າຂອງສາງຕົນເອງ", "📜 ປະຫວັດການເບີກຈ່າຍຂອງສາງຕົນເອງ"],
            horizontal=True,
            key="user_view_mode"
        )

        if user_view == "📜 ປະຫວັດການເບີກຈ່າຍຂອງສາງຕົນເອງ":
            st.write(f"### 📜 ປະຫວັດການເບີກຈ່າຍ / ສົ່ງອອກ — {st.session_state.role}")
            df_hist_own = load_export_history(warehouse_owner=st.session_state.role)
            if not df_hist_own.empty:
                st.dataframe(df_hist_own, use_container_width=True)
            else:
                st.info("ຍັງບໍ່ມີຂໍ້ມູນການສົ່ງອອກຈາກສາງຂອງທ່ານ")
        else:
            df_user = load_data(st.session_state.role)
            display_category_tabs(df_user, prefix_key=f"user_{st.session_state.role}")

    # =========================================================================
    # 🗄️ Database Viewer & CSV Export
    # =========================================================================
    st.markdown("---")
    st.write("### 🗄️ ກວດເບິ່ງແລະດາວໂຫຼດຖານຂໍ້ມູນ (Database Viewer & CSV Export)")

    with st.expander("📊 ຄລິກເພື່ອເບິ່ງຕາຕະລາງຖານຂໍ້ມູນ ແລະ ດາວໂຫຼດ CSV"):
        if IS_ADMIN:
            table_options = [
                "inventory (ຄັງສິນຄ້າທັງໝົດ)",
                "export_history (ປະຫວັດສົ່ງອອກທັງໝົດ)",
                "users (ລາຍຊື່ຜູ້ໃຊ້ງານ)",
                "audit_log (ບັນທຶກການເຄື່ອນໄຫວ)"
            ]
        else:
            # ຜູ້ໃຊ້ທົ່ວໄປ: ເຫັນສະເພາະ inventory ແລະ export_history ຂອງສາງຕົນເອງ, ບໍ່ເຫັນ users/audit_log
            table_options = [
                "inventory (ຄັງສິນຄ້າຂອງທ່ານ)",
                "export_history (ປະຫວັດສົ່ງອອກຂອງທ່ານ)"
            ]

        selected_table = st.selectbox("ເລືອກຕາຕະລາງທີ່ຕ້ອງການກວດສອບ", table_options, key="db_viewer_select")

        conn = get_conn()
        if "inventory" in selected_table:
            if IS_ADMIN:
                view_df = pd.read_sql_query("SELECT * FROM inventory", conn)
            else:
                view_df = pd.read_sql_query("SELECT * FROM inventory WHERE warehouse_owner = ?", conn, params=(st.session_state.role,))
        elif "export_history" in selected_table:
            if IS_ADMIN:
                view_df = pd.read_sql_query("SELECT * FROM export_history", conn)
            else:
                view_df = pd.read_sql_query("SELECT * FROM export_history WHERE warehouse_owner = ?", conn, params=(st.session_state.role,))
        elif "users" in selected_table:
            view_df = pd.read_sql_query("SELECT username, role FROM users", conn)
        elif "audit_log" in selected_table:
            view_df = pd.read_sql_query("SELECT * FROM audit_log ORDER BY performed_at DESC", conn)
        conn.close()

        if not view_df.empty:
            st.dataframe(view_df, use_container_width=True)

            csv_data = view_df.to_csv(index=False).encode('utf-8-sig')
            table_name_raw = selected_table.split(" ")[0]

            st.download_button(
                label=f"📥 ດາວໂຫຼດຕາຕະລາງ {table_name_raw} ເປັນ CSV",
                data=csv_data,
                file_name=f"{table_name_raw}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key=f"download_btn_{table_name_raw}"
            )
        else:
            st.info("ℹ️ ບໍ່ມີຂໍ້ມູນໃນຕາຕະລາງນີ້")