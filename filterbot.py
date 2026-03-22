import imaplib
import smtplib
import email
from email.message import EmailMessage
from email.policy import default
import email.utils
import sqlite3
import re
from collections import Counter
from sievelib.managesieve import Client

# --- CONFIGURATION ---
IMAP_SERVER = "imap.example.com"
SMTP_SERVER = "smtp.example.com"
SIEVE_SERVER = "mail.example.com"
SIEVE_PORT = 4190

BOT_EMAIL = "filterbot@example.com"
BOT_PASSWORD = "changeme123!"

DB_FILE = "filter_bot.db"


REPLY_BODY_PREFIX = "I analyzed your attachments. Here is the proposed filter:"
REPLY_BODY_SUFFIX = "Reply to this email to accept it. If you want to modify it, paste your edited version in your reply."

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS pending_filters
                 (message_id TEXT PRIMARY KEY, user_email TEXT, proposed_filter TEXT)''')
    
    # Table to store user app passwords
    c.execute('''CREATE TABLE IF NOT EXISTS user_credentials
                 (user_email TEXT PRIMARY KEY, app_password TEXT)''')
    conn.commit()
    conn.close()

def get_app_password(user_email):
    """Retrieves the app password for a specific user from the DB."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT app_password FROM user_credentials WHERE user_email=?", (user_email,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

# --- ANALYZE EML ATTACHMENTS ---
def analyze_emls(eml_parts):
    """
    Analyzes attached .eml files for commonalities.
    Prioritizes: 1. Consistent To (+ alias) -> 2. Exact From -> 3. From Domain
    """
    from_addresses = []
    from_domains = []
    to_plus_addresses = []

    total_emls = len(eml_parts)
    if total_emls == 0:
        print("No emails, return none")
        return None

    # 1. Extract data from all attachments
    for part in eml_parts:
        if part.get_content_type() == 'message/rfc822':
            parsed_eml = part.get_payload()[0]
        else:
            raw_bytes = part.get_payload(decode=True)
            if raw_bytes is None:
                print(f"Skipping unreadable attachment: {part.get_filename()}")
                continue
            parsed_eml = email.message_from_bytes(raw_bytes, policy=default)
        
        # Parse 'From' Header
        from_header = parsed_eml.get('From', '')
        _, from_email = email.utils.parseaddr(from_header)

        if from_email:
            from_email = from_email.lower()
            from_addresses.append(from_email)
            
            # Extract Domain
            if '@' in from_email:
                domain = from_email.split('@')[1]
                from_domains.append(domain)

        # Parse 'To' Header (Look for + aliases)
        to_header = parsed_eml.get('To', '')
        _, to_email = email.utils.parseaddr(to_header)
        
        if to_email:
            to_email = to_email.lower()
            local_part = to_email.split('@')[0]
            if '+' in local_part:
                to_plus_addresses.append(to_email)

    # 2. Find the most common occurrences
    def get_top_match(item_list):
        if not item_list:
            return None, 0
        counter = Counter(item_list)
        return counter.most_common(1)[0] 

    best_from_addr, from_addr_count = get_top_match(from_addresses)
    best_domain, domain_count = get_top_match(from_domains)
    best_to_plus, to_plus_count = get_top_match(to_plus_addresses)
    
    sieve_script = None

    # 3. Priority Logic
    if to_plus_count == total_emls:
        sieve_script = f'''if allof (address :is "To" "{best_to_plus}") {{\n    fileinto "Junk";\n    addflag "Junk";\n    stop;\n}}'''
    elif from_addr_count == total_emls:
        sieve_script = f'''if allof (header :contains "From" "{best_from_addr}") {{\n    fileinto "Junk";\n    addflag "Junk";\n   stop;\n}}'''
    elif domain_count == total_emls:
        sieve_script = f'''if allof (header :contains "From" "{best_domain}") {{\n    fileinto "Junk";\n    addflag "Junk";\n   stop;\n}}'''
    elif domain_count > (total_emls * 0.6):
        sieve_script = f'''if allof (header :contains "From" "{best_domain}") {{\n    fileinto "Junk";\n    addflag "Junk";\n   stop;\n}}'''
    
    return sieve_script

# --- MANAGESIEVE INTEGRATION ---
def apply_sieve_filter(user_email, sieve_script):
    """
    Applies the Sieve filter via ManageSieve using the user's App Password.
    Returns (Success_Boolean, Status_Message)
    """
    app_password = get_app_password(user_email)
    
    if not app_password:
        return False, "You do not have an App Password registered with the bot."

    try:
        client = Client(SIEVE_SERVER, SIEVE_PORT)
        
        if not client.connect(user_email, app_password, starttls=True, authmech="PLAIN"):
            return False, "Authentication failed. Your App Password might be incorrect or revoked."
            
        active_script, available_scripts = client.listscripts()
        current_script_content = ""
        
        if active_script:
            current_script_content = client.getscript(active_script)
            if isinstance(current_script_content, bytes):
                current_script_content = current_script_content.decode('utf-8')
        
        # --- IMPROVED SIEVE MERGE LOGIC ---
        # Sieve strictly requires all `require` statements to be at the top of the file.
        clean_new_rule = sieve_script.replace('require ["fileinto"];\n', '').strip()
        
        # Ensure the master script has the necessary 'require' at the very top
        if not current_script_content:
            active_script = "mailcow_bot_filters"
            new_script_content = f'require ["fileinto"];\n{clean_new_rule}'
        else:
            # If the user's script doesn't already have fileinto, we must prepend it
            if '"fileinto"' not in current_script_content and "require ['fileinto']" not in current_script_content:
                current_script_content = 'require ["fileinto"];\n' + current_script_content
                
            new_script_content = current_script_content + '\n\n' + clean_new_rule

        print(f"\n--- ATTEMPTING TO UPLOAD SCRIPT FOR {user_email} ---")
        print(new_script_content)
        print("---------------------------------------------------\n")
        
        # Upload and activate
        putscript_out = client.putscript(active_script, new_script_content)
        #putscript_out = client.putscript(active_script, current_script_content)
        if not putscript_out:
            # Dovecot rejected the script syntax
            print("ERROR: Server rejected the script during putscript.", putscript_out)
            return False, "Failed to upload the new Sieve script to the server. The server rejected the syntax."
            
        if not client.setactive(active_script):
            print("ERROR: Server failed to activate the script.")
            return False, "Failed to activate the updated Sieve script."
            
        return True, "Your filter has been successfully applied and is now active."
        
    except Exception as e:
        print(f"EXCEPTION in ManageSieve: {e}")
        return False, f"A server error occurred while applying the filter: {str(e)}"

# --- MAIN PROCESS LOOP ---
def process_inbox():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(BOT_EMAIL, BOT_PASSWORD)
    mail.select("inbox")

    status, messages = mail.search(None, 'UNSEEN')
    if status != 'OK' or not messages[0]:
        mail.logout()
        return

    for num in messages[0].split():
        status, data = mail.fetch(num, '(RFC822)')
        msg = email.message_from_bytes(data[0][1], policy=default)
        
        # Clean the sender email to ensure precise DB lookups
        raw_from = msg.get('From', '')
        _, user_email = email.utils.parseaddr(raw_from)
        user_email = user_email.lower()
        
        msg_id = msg.get('Message-ID')
        in_reply_to = msg.get('In-Reply-To')
        
        # SCENARIO 1: It's a reply to a proposed filter
        if in_reply_to:
            c.execute("SELECT proposed_filter FROM pending_filters WHERE message_id=?", (in_reply_to,))
            row = c.fetchone()
            if row:
                body = msg.get_body(preferencelist=('plain',)).get_content()
                body_trimmed = ""
                for ln in body.splitlines():
                    if not ln.startswith("> "):
                        continue
                    ln = ln[2:]
                    if len(ln) == 0:
                        continue
                    # seems like wrapping usually happens at about 65 chars not including `> `?
                    if REPLY_BODY_PREFIX[:60] in ln:
                        continue
                    if not ln.startswith('if ') and not body_trimmed:
                        continue
                    body_trimmed+=ln+'\n'
                    if ln == '}':
                        break
                body_trimmed = body_trimmed.replace('\xa0', ' ')
                print("body:", body_trimmed)
                
                success, response_msg = apply_sieve_filter(user_email, body_trimmed)
                
                if success:
                    send_email(user_email, "Filter Applied Successfully", response_msg, msg_id)
                else:
                    send_email(user_email, "Filter Error", f"Could not apply your filter.\n\nError: {response_msg}", msg_id)
                
                c.execute("DELETE FROM pending_filters WHERE message_id=?", (in_reply_to,))
                conn.commit()
                continue
        
        # SCENARIO 2: It's a new submission with .eml attachments
        eml_parts = [part for part in msg.iter_attachments() if part.get_filename() and part.get_filename().endswith('.eml')]
        
        if eml_parts:
            # Pre-flight check: Ensure the user is registered before doing work
            if not get_app_password(user_email):
                error_body = "I received your emails, but you do not have an App Password registered with me. Please generate an App Password in Mailcow, add it to my database, and forward the emails again."
                send_email(user_email, "Registration Required", error_body, msg_id)
                continue

            proposed_sieve = analyze_emls(eml_parts)
            if proposed_sieve:
                reply_body = f"{REPLY_BODY_PREFIX}\n\n{proposed_sieve}\n\n{REPLY_BODY_SUFFIX}"
                reply_msg_id = send_email(user_email, "Re: " + str(msg.get('Subject')), reply_body, msg_id)
                
                c.execute("INSERT INTO pending_filters (message_id, user_email, proposed_filter) VALUES (?, ?, ?)", 
                          (reply_msg_id, user_email, proposed_sieve))
                conn.commit()

    mail.logout()
    conn.close()

# --- SMTP SENDER ---
def send_email(to, subject, body, in_reply_to=None):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = BOT_EMAIL
    msg['To'] = to
    
    msg_id = email.utils.make_msgid(domain=BOT_EMAIL.split('@')[1])
    msg['Message-ID'] = msg_id
    
    if in_reply_to:
        msg['In-Reply-To'] = in_reply_to
        msg['References'] = in_reply_to

    with smtplib.SMTP_SSL(SMTP_SERVER) as server:
        server.login(BOT_EMAIL, BOT_PASSWORD)
        server.send_message(msg)
        
    return msg_id

if __name__ == "__main__":
    init_db()
    print("Bot is polling...")
    process_inbox()
