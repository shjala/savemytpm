#!/bin/bash

set -e

echo "███████╗ ███╗   ███╗ ██╗     "
echo "██╔════╝ ████╗ ████║ ██║     "
echo "█████╗   ██╔████╔██║ ██║     "
echo "██╔══╝   ██║╚██╔╝██║ ██║     "
echo "██║      ██║ ╚═╝ ██║ ███████╗"
echo "╚═╝      ╚═╝     ╚═╝ ╚══════╝ Faulty (TPM) Module Locator"

if [ ! -f /persist/status/uuid ]; then
    echo "ERROR: UUID file not found at /persist/status/uuid"
    exit 1
fi

ID=$(cat /persist/status/uuid)
LOG_DIR="/persist/fscrypt-recovery-$(date +%Y%m%d-%H%M%S).$ID"
LOG_FILE="$LOG_DIR/log.txt"
TAR_FILE="/persist/recovertpm-out-id.$ID.tar.gz"

tar_logs() {
    echo "[===>] Collect the tar file from $TAR_FILE" | tee -a "$LOG_FILE"
    tar -czvf "$TAR_FILE" "$LOG_DIR" >> /dev/null 2>&1
    rm -rf "$LOG_DIR"
}

echo "Creating log directory: $LOG_DIR"
mkdir -p "$LOG_DIR"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create log directory"
    exit 1
fi

echo "Downloading recover-tpm.sh script..." | tee -a "$LOG_FILE"
wget -O recover-tpm.sh https://raw.githubusercontent.com/shjala/savemytpm/refs/heads/experiment-2/recover-tpm.sh 2>&1 | tee -a "$LOG_FILE"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to download recover-tpm.sh" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi
chmod +x recover-tpm.sh 2>&1 | tee -a "$LOG_FILE"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to make recover-tpm.sh executable" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

echo "Exporting plain disk key" | tee -a "$LOG_FILE"
./recover-tpm.sh eve-9.3-export-key-plain 2>&1 | tee -a "$LOG_FILE"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to execute recover-tpm.sh" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi
mv disk-key-plain.id.*.bin /persist/disk-key.bin 2>&1 | tee -a "$LOG_FILE"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to move disk key file to /persist" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

echo "Generating new secret key ..." | tee -a "$LOG_FILE"
SECRET_KEY="$LOG_DIR/secret.key"
while true; do
    head -c 32 /dev/urandom > "$SECRET_KEY"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to generate random key" | tee -a "$LOG_FILE"
        tar_logs
        exit 1
    fi
    
    # Check first byte is not zero
    FIRST_BYTE=$(hexdump -n 1 -e '"%02x"' "$SECRET_KEY")
    if [ "$FIRST_BYTE" != "00" ]; then
        echo "Secret key generated successfully (first byte: 0x$FIRST_BYTE)" | tee -a "$LOG_FILE"
        break
    fi
    echo "Key had leading zero, regenerating..." | tee -a "$LOG_FILE"
done

echo "Resealing the new disk key" | tee -a "$LOG_FILE"
./recover-tpm.sh eve-9.3-reseal "$LOG_DIR/secret.key" 2>&1 | tee -a "$LOG_FILE"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to execute recover-tpm.sh" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

echo "Checking resealed disk key file..." | tee -a "$LOG_FILE"
echo "Exporting plain disk key again" | tee -a "$LOG_FILE"
./recover-tpm.sh eve-9.3-export-key-plain 2>&1 | tee -a "$LOG_FILE"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to execute recover-tpm.sh" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

echo "Comparing original and resealed disk keys..." | tee -a "$LOG_FILE"
diff disk-key-plain.id.*.bin "$LOG_DIR/secret.key" 2>&1 | tee -a "$LOG_FILE"
if [ $? -ne 0 ]; then
    echo "ERROR: Disk keys do not match after resealing" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi
echo "Disk keys match successfully after resealing" | tee -a "$LOG_FILE"
rm disk-key-plain.id.*.bin 2>&1 | tee -a "$LOG_FILE"
if [ $? -ne 0 ]; then
    echo "WARNING: Failed to remove temporary disk key file" | tee -a "$LOG_FILE"
fi

echo "Dumping fscrypt status for /persist..." | tee -a "$LOG_FILE"
/opt/zededa/bin/fscrypt status /persist > "$LOG_DIR/fscrypt-status-persist.txt" 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to get fscrypt status for /persist" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

echo "Dumping fscrypt status for /persist/vault/..." | tee -a "$LOG_FILE"
/opt/zededa/bin/fscrypt status /persist/vault/ > "$LOG_DIR/fscrypt-status-vault.txt" 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to get fscrypt status for /persist/vault/" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

echo "Extracting PROTECTOR ID and POLICY from fscrypt status..." | tee -a "$LOG_FILE"
FSCRYPT_OUTPUT=$(/opt/zededa/bin/fscrypt status /persist 2>&1 | tee -a "$LOG_FILE")
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to get fscrypt status" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

PROTECTOR_ID=$(echo "$FSCRYPT_OUTPUT" | grep -A 1 "PROTECTOR.*LINKED.*DESCRIPTION" | tail -1 | awk '{print $1}')
if [ -z "$PROTECTOR_ID" ]; then
    echo "ERROR: Failed to extract PROTECTOR ID" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi
echo "Vault PROTECTOR ID: $PROTECTOR_ID" | tee -a "$LOG_FILE"

POLICY_ID=$(echo "$FSCRYPT_OUTPUT" | grep -A 1 "POLICY.*UNLOCKED.*PROTECTORS" | tail -1 | awk '{print $1}')
if [ -z "$POLICY_ID" ]; then
    echo "ERROR: Failed to extract POLICY ID" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi
echo "Vault POLICY ID: $POLICY_ID" | tee -a "$LOG_FILE"

echo "Replacing vault key with new secret key..." | tee -a "$LOG_FILE"
/opt/zededa/bin/fscrypt metadata change-passphrase \
    --protector=/persist:$PROTECTOR_ID \
    --source=raw_key \
    --old-key=/persist/disk-key.bin \
    --key="$LOG_DIR/secret.key" \
    --verbose 2>&1 | tee -a "$LOG_FILE"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "ERROR: Failed to change vault key passphrase" | tee -a "$LOG_FILE"
    tar_logs
    exit 1
fi

rm "$LOG_DIR/secret.key" 2>&1 | tee -a "$LOG_FILE"
if [ $? -ne 0 ]; then
    echo "WARNING: Failed to remove temporary secret key file" | tee -a "$LOG_FILE"
fi
rm /persist/disk-key.bin 2>&1 | tee -a "$LOG_FILE"
if [ $? -ne 0 ]; then
    echo "WARNING: Failed to remove temporary disk key file" | tee -a "$LOG_FILE"
fi

echo "Script execution completed successfully." | tee -a "$LOG_FILE"
echo "All logs saved to: $LOG_DIR"
tar_logs

echo "██████╗ ███████╗██████╗  ██████╗  ██████╗ ████████╗"
echo "██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝"
echo "██████╔╝█████╗  ██████╔╝██║   ██║██║   ██║   ██║   "
echo "██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║   ██║   "
echo "██║  ██║███████╗██████╔╝╚██████╔╝╚██████╔╝   ██║   "
echo "╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝    ╚═╝   TO APPLY CHANGES"