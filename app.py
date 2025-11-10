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
from streamlit_cookies_manager import EncryptedCookieManager

# ------------------ CONFIG ------------------
SUPABASE_URL = "https://kwzoutbgvqadmlcmbauq.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt3em91dGJndnFhZG1sY21iYXVxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjAyNTA4MjYsImV4cCI6MjA3NTgyNjgyNn0.Kf9IURiE9CMhDmJvjVg-Jy7zXJx3kiHGypmyo4dCscs"
BASE_URL = "http://checkin-cubanital.streamlit.app"
PASSPHRASE = "MySecretKey12345"
KDF_SALT = b"fixed_salt_2025"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ------------------ KEEP ALIVE ------------------
import threading, time

def keep_alive():
    """Invia una query leggera periodica a Supabase per evitare lo sleep del DB e dell'app."""
    while True:
        try:
            # Query leggera per mantenere viva la connessione
            supabase.table("utenti").select("id").limit(1).execute()
            print(f"[KEEP-ALIVE] Ping inviato {datetime.utcnow().isoformat()}Z")
        except Exception as e:
            print(f"[KEEP-ALIVE] Errore: {e}")
        time.sleep(300)  # ogni 5 minuti

# Avvia il thread del keep-alive in background
threading.Thread(target=keep_alive, daemon=True).start()

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

# ------------------ COOKIE MANAGER LOGIN ------------------
cookies = EncryptedCookieManager(
    prefix="cubanital_",
    password="YourCookieEncryptionPassword123!"  # cambia con una chiave sicura
)
if not cookies.ready():
    st.stop()  # aspetta che i cookie siano pronti

# Logout funzione
def logout():
    cookies["logged_in"] = "False"
    cookies.save()
    st.rerun()

# Controllo login
logged_in = cookies.get("logged_in", "False")
if logged_in != "True":
    st.header("🔐 Login Admin")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "cubanital" and password == "Kabiosile!":
            cookies["logged_in"] = "True"
            cookies.save()
            st.success("✅ Login effettuato")
            st.rerun()
        else:
            st.error("❌ Username o password errati")
    st.stop()


# ------------------ STREAMLIT ------------------
st.set_page_config(page_title="QR Check-in", layout="wide")

# Logo nella sidebar
with st.sidebar:
    try:
        st.image("cubanital_logo.png", use_container_width=True)
    except Exception:
        st.warning("⚠️ Immagine 'cubanital_logo.png' non trovata nella cartella dell'app.")
    
    # Spazio tra logo e pulsante
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    if st.button("Logout", key="logout_sidebar"):
        cookies["logged_in"] = "False"
        cookies.save()
        st.rerun()

# Tabs di navigazione
tab1, tab2, tab3, tab4 = st.tabs([
    "📲 Check-in automatico",
    "📋 Lista partecipanti",
    "🎫 Genera QR",
    "🔍 Visualizza QR"
])

#tab5 = st.empty()  # tab “virtuale” nascosta per UptimeRobot

with tab5.container():
    # Controllo parametri GET
    page_param = st.experimental_get_query_params().get("page", [""])[0]
    if page_param == "Keep+Alive":
        st.write("✅ App attiva")

# --- CHECK-IN AUTOMATICO CON LOGIN ---
with tab1:
    st.header("📲 Check-in automatico")
    
    token_param = st.experimental_get_query_params().get("token")

    if token_param:
        try:
            token_bytes = base64.urlsafe_b64decode(token_param[0])
            decrypted = decrypt_payload(token_bytes).decode("utf-8")
            payload = json.loads(decrypted)

            response = supabase.table("utenti").select("*").eq("token", token_param[0]).execute()

            if response.data and len(response.data) > 0:
                user = response.data[0]
                user_id = user["id"]
                nome = user["nome"]
                cognome = user["cognome"]
                checked = user["checked"]

                if checked:
                    checked_at_val = user.get("checkedat")
                    if isinstance(checked_at_val, str):
                        checked_at_str = checked_at_val
                    elif isinstance(checked_at_val, datetime):
                        checked_at_str = checked_at_val.isoformat()
                    else:
                        checked_at_str = "sconosciuto"
                    st.success(f"✅ Utente già checkato: {nome} {cognome} ({checked_at_str})")
                else:
                    now_str = datetime.utcnow().isoformat() + "Z"
                    supabase.table("checkinlog").update({
                        "checked": True,
                        "checkedat": now_str
                    }).eq("userid", user_id).execute()
                    supabase.table("utenti").update({
                        "checked": True,
                        "checkedat": now_str
                    }).eq("id", user_id).execute()
                    st.success(f"✅ CHECK-IN EFFETTUATO PER {nome} {cognome}")
            else:
                st.error("❌ Persona non registrata.")
        except Exception as e:
            st.error(f"Errore nella decodifica del QR: {e}")
    else:
        st.info("Inquadra il QR code per check-in automatico.")


# --- LISTA PARTECIPANTI ---
with tab2:
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
                try:
                    # Elimina prima i record correlati nella tabella checkinlog
                    supabase.table("checkinlog").delete().eq("userid", user_id).execute()
                    # Poi elimina l'utente
                    supabase.table("utenti").delete().eq("id", user_id).execute()
                    st.success("Utente eliminato ✅")
                    st.rerun()
                except Exception as e:
                    st.error(f"Errore nella cancellazione dell'utente: {e}")

# --- GENERA QR ---
with tab3:
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
            # 🔍 Controllo unicità email
            existing = supabase.table("utenti").select("id").eq("email", email).execute()
            if existing.data and len(existing.data) > 0:
                st.error(f"⚠️ Esiste già un utente registrato con l'email {email}.")
            else:
                # Procedi normalmente
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
with tab4:
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
                # Decodifica QR
                qr_bytes = base64.b64decode(user["qrbase64"])
                img = Image.open(BytesIO(qr_bytes))
                st.image(img, caption=f"QR di {user['nome']} {user['cognome']}", width=300)

                # 🔽 Pulsante per scaricare come PNG
                buf = BytesIO()
                img.save(buf, format="PNG")
                buf.seek(0)

                file_name = f"QR_{user['nome']}_{user['cognome']}.png"
                st.download_button(
                    label="📥 Scarica QR come PNG",
                    data=buf,
                    file_name=file_name,
                    mime="image/png",
                )

            except Exception as e:
                st.error(f"Errore nel decodificare il QR: {e}")

























