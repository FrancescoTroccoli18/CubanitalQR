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
BASE_URL = "https://cubanitalqr-production.up.railway.app/"
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
        "checkedat": None,
        "sendedmail":False
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
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📲 Check-in automatico",
    "📋 Lista partecipanti",
    "🎫 Genera QR",
    "🔍 Visualizza QR",
    "🟢 Keep Alive",
    "📧 Invia Email QR"
])

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
    #st_autorefresh(interval=5000, key="refresh")
    st.header("📋 Lista partecipanti")
    
    if "rows" not in st.session_state:
        st.session_state.rows = fetch_all_users()

    if st.button("Aggiorna lista"):
        st.session_state.rows = fetch_all_users()

    rows = st.session_state.rows
    
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
    tipo = st.selectbox("Tipo di pass", ["FullPack","FullPass","DayPass"])
    if st.button("Genera QR"):
        if not (nome and cognome and email):
            st.error("Inserisci Nome, Cognome ed Email.")
        else:
            # 🔍 Controllo unicità Nome + Cognome
            existing = supabase.table("utenti") \
                .select("id") \
                .eq("nome", nome) \
                .eq("cognome", cognome) \
                .execute()
            
            if existing.data and len(existing.data) > 0:
                st.error(f"⚠️ Esiste già un utente registrato con Nome '{nome}' e Cognome '{cognome}'.")
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

                buf.close()
                del img
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
                qr_bytes = base64.b64decode(user["qrbase64"])
                img = Image.open(BytesIO(qr_bytes))
                st.image(img, caption=f"QR di {user['nome']} {user['cognome']}", width=300)
                buf = BytesIO()
                img.save(buf, format="PNG")
                buf.seek(0)
                st.download_button(
                    label="📥 Scarica QR come PNG",
                    data=buf,
                    file_name=f"QR_{user['nome']}_{user['cognome']}.png",
                    mime="image/png",
                )
                buf.close()
                del img
            except Exception as e:
                st.error(f"Errore nel decodificare il QR: {e}")
with tab5:
    st.header("🟢 Keep Alive")
    st.write("✅ App attiva")
    st.info("Questa tab serve per mantenere l'app Streamlit e il database Supabase attivi.")


# --- INVIA EMAIL QR (solo utenti senza email inviata) ---
with tab6:
    st.header("📧 Invia email QR ai partecipanti (solo non inviati)")

    # Prelevo utenti e checkinlog
    utenti = fetch_all_users()
    checkin = supabase.table("checkinlog").select("*").execute().data

    # Join manuale utenti ↔ checkinlog
    lista = []
    for u in utenti:
        cl = next((c for c in checkin if c["userid"] == u["id"]), None)
        if cl:
            lista.append({**u, **cl})

    # Filtra solo quelli senza sendedmail
    not_sent = [u for u in lista if not u.get("sendedmail", False)]

    st.info(f"📌 Trovati **{len(not_sent)} utenti** senza email inviata.")

    # --- Mostra tabella con stato invio ---
    st.subheader("📋 Lista partecipanti e stato email")
    if lista:
        for u in lista:
            cols = st.columns([2,2,3,1,1])
            cols[0].write(u["nome"])
            cols[1].write(u["cognome"])
            cols[2].write(u["email"])
            # Mostra anteprima QR piccola
            try:
                qr_bytes = base64.b64decode(u["qrbase64"])
                img = Image.open(BytesIO(qr_bytes))
                cols[3].image(img, width=50)
            except:
                cols[3].write("❌")
            # Mostra stato email
            if u.get("sendedmail"):
                cols[4].success("✅")
            else:
                cols[4].error("❌")
    else:
        st.warning("Nessun partecipante registrato.")

    # SMTP CONFIG
    st.subheader("📮 Impostazioni SMTP")
    smtp_server = st.text_input("SMTP Server", "smtp.gmail.com")
    smtp_port = st.number_input("Porta", 587)
    smtp_user = "afrocubaneventcubanital@gmail.com"
    smtp_pass = "Kabiosile!"

    st.subheader("📑 Template email")
    subject = st.text_input("Oggetto", "QR – CUBANITAL 2026")
    body = st.text_area(
        """
        <h3>Ciao {{nome}}</h3>
        desideriamo ringraziarti per aver preso parte al nostro evento CUBANITAL 2026, che si svolgerà il 24 e 25 gennaio. La sua presenza contribuisce al successo dell’iniziativa e siamo lieti di averti con noi.
         
        In allegato troverai il QR Code del {{tipo_pass}} CUBANITAL 2026.     
        Il QR Code ti permetterà di accedere a tutte le attività comprese nel pacchetto.
         
        Ti ringraziamo ancora una volta per la partecipazione e restiamo a disposizione per qualsiasi necessità.
         
        Cordiali saluti,
        L’ORGANIZZAZIONE CUBANITAL 2026

        --------------------------------------------------

        <h3>Hola, {{nome}}</h3>
        queremos agradecerte por participar en nuestro evento CUBANITAL 2026, que se llevará a cabo los días 24 y 25 de enero. Tu presencia contribuye al éxito de la iniciativa y nos complace tenerte con nosotros.
         
        Adjuntamos el código QR del {{tipo_pass}} CUBANITAL 2026.     
        El código QR te permitirá acceder a todas las actividades incluidas en el paquete.
         
        Te agradecemos una vez más tu participación y quedamos a tu disposición para cualquier necesidad.
         
        Atentamente,
        LA ORGANIZACIÓN CUBANITAL 2026.

        -------------------------------------------------

        <h3>Hello {{nome}}</h3>
        We would like to thank you for taking part in our CUBANITAL 2026 event, which will take place on January 24 and 25. Your presence contributes to the success of the initiative and we are delighted to have you with us.
         
        Attached you will find the QR Code for your CUBANITAL 2026 {{tipo_pass}}.     
        The QR Code will allow you to access all the activities included in the package.
         
        Thank you once again for participating. Please do not hesitate to contact us if you have any questions.
         
        Best regards,
        THE CUBANITAL 2026 ORGANIZATION

        QR Code:</p><img src='cid:qrimg'>
        
        """
    )

    # Funzione per invio email
    def send_email(to_email, qr_bytes, nome, tipo_pass):
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.image import MIMEImage

        msg = MIMEMultipart("related")
        msg["Subject"] = subject
        msg["From"] = smtp_user
        msg["To"] = to_email

        html = body.replace("{{nome}}", nome).replace("{{tipo_pass}}", tipo_pass)

        alt = MIMEMultipart("alternative")
        msg.attach(alt)
        alt.attach(MIMEText(html, "html"))

        img = MIMEImage(qr_bytes)
        img.add_header("Content-ID", "<qrimg>")
        msg.attach(img)

        with smtplib.SMTP(smtp_server, smtp_port) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)

    # Bottone invio email
    if st.button("📤 INVIA EMAIL A TUTTI I NON INVIATI"):
        st.write(not_sent)
        for u in not_sent[0]:
            try:
                qr_bytes = base64.b64decode(u["qrbase64"])
                #send_email(u["email"], qr_bytes, u["nome"], u.get("tipo"))
                send_email("capriolooscuro@gmail.com", qr_bytes, "Francesco", u.get("tipo"))

                # Aggiorna checkinlog.sendedmail
                #supabase.table("checkinlog").update({
                #    "sendedmail": True
                #}).eq("userid", u["id"]).execute()

                st.success(f"📨 Email inviata a {u['nome']} {u['cognome']}")
            except Exception as e:
                st.error(f"Errore: {e}")

        st.success("✅ Tutte le email sono state elaborate!")














