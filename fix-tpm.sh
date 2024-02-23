#!/bin/sh

ID=$(cat /persist/status/uuid)
mkdir recovertpm-out
OUTDIR=$PWD/recovertpm-out
KEY_PLAIN=$OUTDIR/disk-key-plain.id.$ID.bin
KEY_ENCRYPTED=$OUTDIR/disk-key-enc.id.$ID.txt
LOG=$OUTDIR/recovertpm.log
TAR_FILE=$PWD/recovertpm-out-id.$ID.tar.gz
DEVICE_CERT_NAME="device.cert.pem"
DEVICE_CERT_PATH="/config/$DEVICE_CERT_NAME"
EVE_RELEASE=$(cat /run/eve-release)
DEVICE_CERT_TPM_INDEX=0x817FFFFF
VAULT_PUB_INDEX=0x1900000
VAULT_PRIV_INDEX=0x1800000
SRK_INDEX=0x81000002
ECDH_INDEX=0x81000005
NEW_ECDH_INDEX=0x81000003
PCR_HASH="sha256"
PCR_INDEX="0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14"
OLD_RELEASE=0

tar_logs() {
    echo "[===>] Collect the tar file" | tee -a $LOG
    tar -czvf $TAR_FILE $OUTDIR >> /dev/null 2>&1
    rm $LOG
    rm -rf $OUTDIR
}

# remove the old savemytpm
if [ -f savemytpm ]; then
    rm savemytpm
fi

# download the savemytpm
arch=$(arch)
if [ "$arch" = 'x86_64' ]; then 
    wget https://github.com/shjala/savemytpm/raw/experiment/pre-built/savemytpm.amd64 > /dev/null 2>&1
    mv savemytpm.amd64 savemytpm
    chmod +x savemytpm
elif [ "$arch" = 'aarch64' ]; then
    wget https://github.com/shjala/savemytpm/raw/experiment/pre-built/savemytpm.arm64 > /dev/null 2>&1
    mv savemytpm.arm64 savemytpm
    chmod +x savemytpm
fi

# get eve major and minor version
EVE_MAJOR=$(echo $EVE_RELEASE | grep -Eo '^[0-9]+\.[0-9]+' | awk -F \. {'print $1'})
EVE_MINOR=$(echo $EVE_RELEASE | grep -Eo '^[0-9]+\.[0-9]+' | awk -F \. {'print $2'})
if [ $EVE_MAJOR -lt 9 ]; then
    OLD_RELEASE=1
elif [ $EVE_MAJOR -eq 9 ]; then
    if [ $EVE_MINOR -lt 4 ]; then
        OLD_RELEASE=1
    else
        OLD_RELEASE=0
    fi
fi

# adjust parameters based on eve version
if [ $OLD_RELEASE -eq 1 ]; then
    PCR_HASH="sha1"
    PCR_INDEX="0, 1, 2, 3, 4, 6, 7, 8, 9, 13"
fi

echo "[===>] Exporting disk key in plain text format... " | tee -a $LOG
./savemytpm --export-plain --output $KEY_PLAIN \
            --pub-index $VAULT_PUB_INDEX --priv-index $VAULT_PRIV_INDEX --srk-index $SRK_INDEX \
            --pcr-hash $PCR_HASH --pcr-index "$PCR_INDEX"
if [ $? -ne 0 ]; then
    echo "[===>] ERR - Exporting disk key failed, can't do anything more :(" | tee -a $LOG
    exit 1
fi

echo "[===>] Checking TPM and disk certs..."
./savemytpm --check-cert --cert-path $DEVICE_CERT_PATH --dev-key-index 0x817FFFFF --log $LOG
if [ $? -ne 0 ]; then
    echo "[===>] ERR - Checking TPM and disk certs failed, can't do anything more :(" | tee -a $LOG
    tar_logs
    exit 1
fi

echo "[===>] Exporting disk key in cloud format... " | tee -a $LOG
./savemytpm --export-cloud --output $KEY_ENCRYPTED \
            --pub-index $VAULT_PUB_INDEX --priv-index $VAULT_PRIV_INDEX --srk-index $SRK_INDEX \
            --ecdh-index $ECDH_INDEX --dev-key-index $DEVICE_CERT_TPM_INDEX \
            -pcr-hash $PCR_HASH --pcr-index "$PCR_INDEX" --log $LOG
if [ $? -ne 0 ] || [ "${1-}" = "--force" ]; then
    echo "[===>] ERR - Exporting cloud format disk key failed, initating recovery process..." | tee -a $LOG
    echo "[===>] Generating a temporary ECDH key." | tee -a $LOG
    ./savemytpm --gen-ecdh --ecdh-index $NEW_ECDH_INDEX
    if [ $? -ne 0 ]; then
        echo "[===>] ERR - Generating a temporary ECDH key failed, can't recover from this..." | tee -a $LOG
        tar_logs
        exit 1
    fi
    echo "[===>] Temporary ECDH generated, trying the export process again..." | tee -a $LOG
    ./savemytpm --export-cloud --output $KEY_ENCRYPTED \
                --pub-index $VAULT_PUB_INDEX --priv-index $VAULT_PRIV_INDEX --srk-index $SRK_INDEX \
                --ecdh-index $NEW_ECDH_INDEX --dev-key-index $DEVICE_CERT_TPM_INDEX \
                -pcr-hash $PCR_HASH --pcr-index "$PCR_INDEX" --log $LOG
    if [ $? -ne 0 ]; then
        echo "[===>] ERR - Exporting cloud format disk key failed, can't recover from this..." | tee -a $LOG
        tar_logs
        exit 1
    fi
    echo "[===>] Exporting cloud format with temporary key successfull." | tee -a $LOG
    echo "[===>] Removing the temporary ECDH key." | tee -a $LOG
    ./savemytpm --remove-ecdh --ecdh-index $NEW_ECDH_INDEX --log $LOG
    if [ $? -ne 0 ]; then
        echo "[===>] ERR - Removing temporary ECDH key failed, continuing ..." | tee -a $LOG
    fi
    echo "[===>] Temporary ECDH removed." | tee -a $LOG
    echo "[===>] Replacing the old ECDH key with fresh key..." | tee -a $LOG
    ./savemytpm --remove-ecdh --ecdh-index $ECDH_INDEX --log $LOG
    if [ $? -ne 0 ]; then
        echo "[===>] ERR - Removing old ecdh key failed, continuing..." | tee -a $LOG
    fi
    ./savemytpm --gen-ecdh --ecdh-index $ECDH_INDEX --log $LOG
    if [ $? -ne 0 ]; then
        echo "[===>] ERR - Replacing ECDH key failed, can't recover from this..." | tee -a $LOG
        tar_logs
        exit 1
    fi
    echo "[===>] System ECDH key replaced in TPM." | tee -a $LOG
    echo "[===>] Writing ECDH cert to disk..." | tee -a $LOG
    ./savemytpm --write-ecdh-cert --ecdh-index $ECDH_INDEX \
                --dev-key-index $DEVICE_CERT_TPM_INDEX \
                --cert-path $DEVICE_CERT_PATH --log $LOG
    if [ $? -ne 0 ]; then
        echo "[===>] ERR - Writing ECDH cert to disk failed, can't recover from this ..." | tee -a $LOG
        tar_logs
        exit 1
    fi
    echo "[===>] Exporting cloud format disk key again..." | tee -a $LOG
    ./savemytpm --export-cloud --output $KEY_ENCRYPTED \
                --pub-index $VAULT_PUB_INDEX --priv-index $VAULT_PRIV_INDEX --srk-index $SRK_INDEX \
                --ecdh-index $ECDH_INDEX --dev-key-index $DEVICE_CERT_TPM_INDEX \
                -pcr-hash $PCR_HASH --pcr-index "$PCR_INDEX" --log $LOG
    if [ $? -ne 0 ]; then
        echo "[===>] ERR - Exporting cloud format disk key failed, can't recover from this..." | tee -a $LOG
        tar_logs
        exit 1
    fi
    echo "[===>] Exporting cloud format disk key successfull." | tee -a $LOG
    tar_logs
    exit 0
else
    echo "[===>] Exporting cloud format disk key successfull." | tee -a $LOG
    tar_logs
    exit 0
fi