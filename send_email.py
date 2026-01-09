from supabase import create_client
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import smtplib
from io import BytesIO
from PIL import Image
import argparse

# ------------------ CONFIG ------------------
SUPABASE_URL = "https://kwzoutbgvqadmlcmbauq.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt3em91dGJndnFhZG1sY21iYXVxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjAyNTA4MjYsImV4cCI6MjA3NTgyNjgyNn0.Kf9IURiE9CMhDmJvjVg-Jy7zXJx3kiHGypmyo4dCscs"

# SMTP Gmail
SMTP_USER = "afrocubaneventcubanital@gmail.com"
SMTP_PASS = "ohas bhgp acbm gcuy"

# Connessione a Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ------------------ FUNZIONI ------------------
def fetch_users_to_email():
    """Recupera utenti dal DB Supabase che non hanno ancora ricevuto l'email"""
    utenti = supabase.table("utenti").select("*").execute().data
    checkin = supabase.table("checkinlog").select("*").execute().data
    lista = []
    for u in utenti:
        cl = next((c for c in checkin if c["userid"] == u["id"]), None)
        if cl and not cl.get("sendedmail", False):
            lista.append({**u, **cl})
    return lista

def fetch_users_by_ids(user_ids):
    """Recupera utenti da DB per ID"""
    utenti = supabase.table("utenti").select("*").in_("id", user_ids).execute().data
    checkin = supabase.table("checkinlog").select("*").in_("userid", user_ids).execute().data
    lista = []
    for u in utenti:
        cl = next((c for c in checkin if c["userid"] == u["id"]), {})
        lista.append({**u, **cl})
    return lista

def fetch_users_by_emails(emails):
    """Recupera utenti da DB per email"""
    utenti = supabase.table("utenti").select("*").in_("email", emails).execute().data
    checkin = supabase.table("checkinlog").select("*").execute().data
    lista = []
    for u in utenti:
        cl = next((c for c in checkin if c["userid"] == u["id"]), {})
        lista.append({**u, **cl})
    return lista

def send_email(to_email, qr_bytes, nome, tipo_pass):
    """Invia l'email con QR allegato"""
    subject = "QR – CUBANITAL 2026"
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; background-color: #f7f7f7; padding: 20px; background-image: url('cid:sfondo'); background-size: cover; background-position: center; background-repeat: no-repeat;
        ">
        <div style="max-width: 600px; margin: auto; background-color: rgba(224,224,224,0.85); padding: 50px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1);">
    
          <!-- Italiano -->
          <h3 style="color:#2c3e50;">Ciao {nome},</h3>
          <p>Desideriamo ringraziarti per aver preso parte al nostro evento <strong>CUBANITAL 2026</strong>, che si svolgerà il 24 e 25 gennaio. 
          La tua presenza contribuisce al successo dell’iniziativa e siamo lieti di averti con noi.</p>
    
          <p>In allegato troverai il QR Code del <strong>{tipo_pass} CUBANITAL 2026</strong>. 
          Il QR Code ti permetterà di accedere a tutte le attività comprese nel pacchetto.</p>
    
          <p>Ti ringraziamo ancora una volta per la partecipazione e restiamo a disposizione per qualsiasi necessità.</p>
    
          <p>Cordiali saluti,<br><strong>L’ORGANIZZAZIONE CUBANITAL 2026</strong></p>
    
          <hr style="border:1px solid #000000; margin:30px 0;">
    
          <!-- Spagnolo -->
          <h3 style="color:#2c3e50;">Hola, {nome}</h3>
          <p>Queremos agradecerte por participar en nuestro evento <strong>CUBANITAL 2026</strong>, que se llevará a cabo los días 24 y 25 de enero. 
          Tu presencia contribuye al éxito de la iniciativa y nos complace tenerte con nosotros.</p>
    
          <p>Adjuntamos el código QR del <strong>{tipo_pass} CUBANITAL 2026</strong>. 
          El código QR te permitirá acceder a todas las actividades incluidas en el paquete.</p>
    
          <p>Te agradecemos una vez más tu participación y quedamos a tu disposición para cualquier necesidad.</p>
    
          <p>Atentamente,<br><strong>LA ORGANIZACIÓN CUBANITAL 2026</strong></p>
    
          <hr style="border:1px solid #000000; margin:30px 0;">
    
          <!-- Inglese -->
          <h3 style="color:#2c3e50;">Hello {nome},</h3>
          <p>We would like to thank you for taking part in our <strong>CUBANITAL 2026</strong> event, which will take place on January 24 and 25. 
          Your presence contributes to the success of the initiative and we are delighted to have you with us.</p>
    
          <p>Attached you will find the QR Code for your <strong>{tipo_pass} CUBANITAL 2026</strong>. 
          The QR Code will allow you to access all the activities included in the package.</p>
    
          <p>Thank you once again for participating. Please do not hesitate to contact us if you have any questions.</p>
    
          <p>Best regards,<br><strong>THE CUBANITAL 2026 ORGANIZATION</strong></p>
    
          <div style="text-align:center; margin-top:20px;">
            <img src="cid:qrimg" alt="QR Code" style="width:200px; height:auto;"/>
          </div>
    
        </div>
      </body>
    </html>
    """

    msg = MIMEMultipart("related")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    alt = MIMEMultipart("alternative")
    msg.attach(alt)
    alt.attach(MIMEText(body, "html"))

    # QR Code
    img = MIMEImage(qr_bytes)
    img.add_header("Content-ID", "<qrimg>")
    msg.attach(img)

    # Immagine sfondo
    with open("images/locandina_cubanital.jpg", "rb") as f:
        img = MIMEImage(f.read())
        img.add_header("Content-ID", "<sfondo>")
        img.add_header("Content-Disposition", "inline", filename="locandina_cubanital.jpg")
        msg.attach(img)

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

def mark_email_sent(user_id):
    """Aggiorna checkinlog per segnalare email inviata"""
    supabase.table("checkinlog").update({"sendedmail": True}).eq("userid", user_id).execute()

# ------------------ SCRIPT PRINCIPALE ------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Invio email QR CUBANITAL 2026")
    parser.add_argument("--ids", help="Lista ID utenti separati da virgola")
    parser.add_argument("--emails", help="Lista email separate da virgola")
    args = parser.parse_args()

    if args.ids:
        user_ids = [int(i) for i in args.ids.split(",")]
        utenti_da_inviare = fetch_users_by_ids(user_ids)
        print(f"📌 Modalità MANUALE per ID: {user_ids}")

    elif args.emails:
        emails = [e.strip() for e in args.emails.split(",")]
        utenti_da_inviare = fetch_users_by_emails(emails)
        print(f"📌 Modalità MANUALE per EMAIL: {emails}")

    else:
        utenti_da_inviare = fetch_users_to_email()
        print("📌 Modalità DB automatica (email non inviate)")

    print(f"Trovati {len(utenti_da_inviare)} utenti da contattare...")

    for u in utenti_da_inviare:
        try:
            qr_bytes = base64.b64decode(u["qrbase64"])
            send_email(u["email"], qr_bytes, u["nome"], u["tipo"])
            mark_email_sent(u["id"])
            print(f"✅ Email inviata a {u['nome']} {u['cognome']} ({u['email']})")
        except Exception as e:
            print(f"❌ Errore invio email a {u['nome']} {u['cognome']}: {e}")

    print("✅ Tutte le email elaborate.")
