#!/bin/bash

# ==============================================================================
# Configuration
# ==============================================================================
ALLOWED_DOMAIN="example.com"
SIEVE_SCRIPT_NAME="whitelist_only" 

MAIL_USER="filterbot@${ALLOWED_DOMAIN}"
MAIL_PASS="changeme123!"
SIEVE_SERVER="mail.${ALLOWED_DOMAIN}"
SIEVE_PORT="4190"

# ==============================================================================
# Sieve Generation
# ==============================================================================
TMP_SIEVE=$(mktemp)
TMP_PASS=$(mktemp) # Secure temporary file for the password

# Write the Sieve rule
cat <<EOF > "$TMP_SIEVE"
require ["fileinto"];

# Whitelist rule:
# If the sender's domain is NOT $ALLOWED_DOMAIN, silently drop the mail.

if not address :domain "From" "$ALLOWED_DOMAIN" {
    discard;
    stop;
}
EOF

# Write the password to the temporary file securely without trailing newlines
echo -n "$MAIL_PASS" > "$TMP_PASS"

# ==============================================================================
# Upload & Activate via sieve-connect
# ==============================================================================
echo "Connecting to $SIEVE_SERVER on port $SIEVE_PORT..."

# Open file descriptor 4 and link it to our password file
exec 4< "$TMP_PASS"

# Explicitly define --localsieve and --remotesieve alongside the --upload action
sieve-connect \
    --server "$SIEVE_SERVER" \
    --port "$SIEVE_PORT" \
    --user "$MAIL_USER" \
    --passwordfd 4 \
    --localsieve "$TMP_SIEVE" \
    --remotesieve "$SIEVE_SCRIPT_NAME" \
    --upload \
    --notlsverify 

# Close the file descriptor 
exec 4<&-

if [ $? -eq 0 ]; then
    echo "Success! Sieve rule uploaded."
    echo "Activating the rule..."
    
    # Re-open file descriptor 4 for the activation command
    exec 4< "$TMP_PASS"
    
    # Explicitly use --remotesieve so the --activate flag knows what to target
    sieve-connect \
        --server "$SIEVE_SERVER" \
        --port "$SIEVE_PORT" \
        --user "$MAIL_USER" \
        --passwordfd 4 \
        --remotesieve "$SIEVE_SCRIPT_NAME" \
        --activate \
        --notlsverify
        
    # Close it again
    exec 4<&-
        
    if [ $? -eq 0 ]; then
        echo "Rule '$SIEVE_SCRIPT_NAME' is now active!"
    else
        echo "Error: Failed to activate the Sieve rule."
    fi
else
    echo "Error: Failed to upload the Sieve rule."
fi

# ==============================================================================
# Cleanup
# ==============================================================================
rm -f "$TMP_SIEVE"
rm -f "$TMP_PASS"
