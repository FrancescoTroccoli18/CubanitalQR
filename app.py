import streamlit as st
from supabase import create_client
import base64, json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import qrcode
from io import BytesIO
from PIL import Image
from streamlit_autorefresh import st_autorefresh

# ------------------ CONFIG ------------------
SUPABASE_URL = "https://kwzoutbgvqadmlcmbauq.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt3em91dGJndnFhZG1sY21iYXVxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjAyNTA4MjYsImV4cCI6MjA3NTgyNjgyNn0.Kf9IURiE9CMhDmJvjVg-Jy7zXJx3kiHGypmyo4dCscs"
BASE_URL = "http://cubanitalqr-ead49sf9t8xndcwlazlhuv.streamlit.app"
PASSPHRASE = "MySecretKey12345"
KDF_SALT = b"fixed_salt_2025"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ------------------ CRITTOGRAFIA ------------------
def derive_fernet_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def encrypt_payload(payload_bytes: bytes) -> bytes:
    f = Fernet(derive_fernet_key(PASSPHRASE))
    return f.encrypt(payload_bytes)

def decrypt_payload(token_bytes: bytes) -> bytes:
    f = Fernet(derive_fernet_key(PASSPHRASE))
    return f.decrypt(token_bytes)

def generate_qr_from_text(text: str) -> Image.Image:
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(text)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")

# ------------------ DB UTILITY ------------------
def fetch_all_users():
    try:
        response = supabase.table("utenti").select("*").order("id", desc=True).execute()
        return response.data
    except Exception as e:
        st.error(f"Errore API Supabase: {e}")
        return []

def add_user_sql(record):
    result = supabase.table("utenti").insert({
        "tipo": record["tipo"],
        "nome": record["nome"],
        "cognome": record["cognome"],
        "telefono": record["telefono"],
        "email": record["email"],
        "token": record["token"],
        "qrbase64": record["qr_base64"],
        "checked": False,
    }).execute()
    user_id = result.data[0]["id"]

    supabase.table("checkinlog").insert({
        "userid": user_id,
        "checked": False,
        "checkedat": None
    }).execute()
    return user_id

def do_checkin_sql(user_id, checked=True):
    supabase.table("checkinlog").update({
        "checked": checked,
        "checkedat": datetime.utcnow() if checked else None
    }).eq("userid", user_id).execute()

    supabase.table("utenti").update({
        "checked": checked,
        "checkedat": datetime.utcnow() if checked else None
    }).eq("id", user_id).execute()

# ------------------ STREAMLIT ------------------
st.set_page_config(page_title="QR Check-in", layout="wide")
PAGES = ["Check-in automatico", "Lista partecipanti", "Genera QR", "Visualizza QR"]
page = st.sidebar.selectbox("Menu", PAGES)

# --- CHECK-IN AUTOMATICO ---
if page == "Check-in automatico":
    st.header("📲 Check-in automatico")
    token_param = st.experimental_get_query_params().get("token")

    if token_param:
        try:
            # Decodifica token dal QR
            token_bytes = base64.urlsafe_b64decode(token_param[0])
            payload = json.loads(decrypt_payload(token_bytes).decode("utf-8"))

            # Controlla se l'utente esiste
            response = supabase.table("utenti").select("*").eq("token", token_param[0]).execute()
            if response.data:
                user = response.data[0]
                user_id = user["id"]
                nome = user["nome"]
                cognome = user["cognome"]
                checked = user["checked"]

                if checked:
                    checked_at_str = user["checkedat"].isoformat() if user["checkedat"] else "sconosciuto"
                    st.success(f"✅ Utente già checkato: {nome} {cognome} alle {checked_at_str}")
                else:
                    # Aggiorna CheckinLog
                    supabase.table("checkinlog").update({
                        "checked": True,
                        "checkedat": datetime.utcnow()
                    }).eq("userid", user_id).execute()

                    # Aggiorna Utenti
                    supabase.table("utenti").update({
                        "checked": True,
                        "checkedat": datetime.utcnow()
                    }).eq("id", user_id).execute()

                    st.success(f"✅ CHECK-IN EFFETTUATO PER {nome} {cognome}")
            else:
                st.error("❌ Persona non registrata.")
        except Exception as e:
            st.error(f"Errore nella decodifica del QR: {e}")
    else:
        st.info("Inquadra il QR code per check-in automatico.")

# --- LISTA PARTECIPANTI ---
if page == "Lista partecipanti":
    st_autorefresh(interval=5000, key="refresh")
    st.header("📋 Lista partecipanti")
    rows = fetch_all_users()
    if not rows:
        st.warning("Nessun partecipante registrato.")
    else:
        col1, col2 = st.columns([1,1])
        with col1:
            tipi_disponibili = sorted(list(set(r["tipo"] for r in rows if r.get("tipo"))))
            tipi_disponibili.insert(0, "Tutti")
            filtro_tipo = st.selectbox("Tipo", tipi_disponibili)
        with col2:
            filtro_checked = st.selectbox("Stato", ["Tutti","Checkati","Non checkati"])
        if filtro_tipo != "Tutti":
            rows = [r for r in rows if r["tipo"] == filtro_tipo]
        if filtro_checked == "Checkati":
            rows = [r for r in rows if r["checked"]]
        elif filtro_checked == "Non checkati":
            rows = [r for r in rows if not r["checked"]]
        rows.sort(key=lambda x: (x["checkedat"] is not None, x["checkedat"] or datetime.min))

        header_cols = st.columns([2,2,3,2,2,1,1])
        headers = ["Nome","Cognome","Email","Telefono","Tipo","Checked","Elimina"]
        for col, title in zip(header_cols, headers):
            col.markdown(f"**{title}**")

        for r in rows:
            cols = st.columns([2,2,3,2,2,1,1])
            user_id = r["id"]
            cols[0].write(r["nome"])
            cols[1].write(r["cognome"])
            cols[2].write(r["email"])
            cols[3].write(r["telefono"])
            cols[4].write(r["tipo"])
            chk_key = f"chk_{user_id}"
            checked_from_db = r["checked"]
            if chk_key not in st.session_state or st.session_state[chk_key] != checked_from_db:
                st.session_state[chk_key] = checked_from_db
            new_val = cols[5].checkbox("", key=chk_key)
            if new_val != st.session_state[chk_key]:
                do_checkin_sql(user_id, new_val)
                st.session_state[chk_key] = new_val
                st.rerun()
            if cols[6].button("🗑️", key=f"del_{user_id}"):
                supabase.table("utenti").delete().eq("id", user_id).execute()
                st.rerun()

# --- GENERA QR ---
elif page == "Genera QR":
    st.header("🎫 Genera QR per partecipante")
    nome = st.text_input("Nome")
    cognome = st.text_input("Cognome")
    telefono = st.text_input("Telefono")
    email = st.text_input("Email")
    tipo = st.selectbox("Tipo di pass", ["FullPack","FullPass"])
    if st.button("Genera QR"):
        if not (nome and cognome and email):
            st.error("Inserisci Nome, Cognome ed Email.")
        else:
            payload = {
                "tipo": tipo,
                "nome": nome,
                "cognome": cognome,
                "telefono": telefono,
                "email": email,
                "created_at": datetime.utcnow().isoformat()+"Z",
            }
            token_bytes = encrypt_payload(json.dumps(payload).encode())
            token_str = base64.urlsafe_b64encode(token_bytes).decode()
            url = f"{BASE_URL}?token={token_str}"
            img = generate_qr_from_text(url)

            buf = BytesIO()
            img.save(buf, format="PNG")
            qr_base64 = base64.b64encode(buf.getvalue()).decode()

            record = {
                "tipo": tipo,
                "nome": nome,
                "cognome": cognome,
                "telefono": telefono,
                "email": email,
                "token": token_str,
                "qr_base64": qr_base64,
            }
            add_user_sql(record)
            st.image(img, width=200)
            st.success(f"✅ QR creato per {nome} {cognome}")

# --- VISUALIZZA QR ---
elif page == "Visualizza QR":
    st.header("🔍 Visualizza QR partecipante")
    rows = fetch_all_users()
    if not rows:
        st.warning("Nessun partecipante registrato.")
    else:
        options = [f"{r['nome']} {r['cognome']} ({r['email']})" for r in rows]
        selected = st.selectbox("Seleziona partecipante", options)
        if selected:
            user = rows[options.index(selected)]
            try:
                qr_bytes = base64.b64decode(user["qrbase64"])
                img = Image.open(BytesIO(qr_bytes))
                st.image(img, caption=f"QR di {user['nome']} {user['cognome']}", width=300)
            except Exception as e:
                st.error(f"Errore nel decodificare il QR: {e}")


