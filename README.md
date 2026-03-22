# filterbot
Tool compatible with Sieve style email filters to easily add email rules to mark junk mail as junk by forwarding mail to a specific mailbox.
This has been tested specifically with:
- Mailcow mailserver (dockerized Postfix/Dovecot)
- Evolution and K-9 Mail clients

# Usage:
1. Create a `filterbot` inbox on your domain
2. Create credentials (preferrably an IMAP/SMTP-only app password) for the `filterbot` inbox
3. Put these credentials into `filterbot.py` (as well as other pertinent information like your mail server address, etc. The default config assumes you use separate hostnames for all three but works fine if they're all set to the same if you have one server managing them all)
4. Create an app password for any user which wants to use filterbot (this should ideally be a sieve-only app password)
5. Install dependencies with `apt install python3-sievelib sieve-connect`
  1. `sieve-connect` is only used during the next step and is not required for continual deployment
6. (Optional but recommended) Edit `create_filterbot_account_sieve.sh` with the filterbot mailbox credentials and mailserver then execute. This restricts what domains can send email to filterbot to prevent sending spam replies
7. Run filterbot once by hand to generate the db and tables
8. Run this python one-liner to store the user's app password into the database (run once per user) `python3 -c "import sqlite3; conn = sqlite3.connect('filter_bot.db'); c = conn.cursor(); c.execute(\"INSERT OR REPLACE INTO user_credentials (user_email, app_password) VALUES ('user@example.com', 'changeme456!')\"); conn.commit(); conn.close(); print('Credentials added successfully!')"`
9. Create a cronjob to execute `python3 filterbot.py` on a regular basis (note that it creates a local database, so you should consider having it `cd` into this repository first)
10. Take your spam email and forward it to filterbot as an attachment. If you attach multiple emails at once, it will pick out common characteristics of all of them and pick what it thinks is the best filter. It will then reply with all filters available (with three of them commented out and the preferred one uncommented.)
11. If you agree with its choice, reply to the email with filterbot's reply quoted (ie in your reply but prefixed with `> `)
12. If you disagree with its choice, either uncomment the filter you desire (and comment out/delete the ones you don't like) OR don't reply at all. If you do not reply, no action will be taken.
13. Once filterbot runs again, it will create the rule and return a success message.


# Notes:
This was vibe-coded-then-tweaked in an afternoon, it's not pretty, and it *mostly* works. I do not promise/commit to fixing bugs if they arise. I will review any PRs which are made to this repository. 

None of the filtering logic uses any AI or LLMs. It's all pure pattern recognition.

This code has been loosely tested, I make to promises that it will not cause damage. Use this at your own risk.
