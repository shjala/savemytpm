#!/bin/sh

if [ $# -eq 0 ]; then
    echo "Usage: run.sh <command>"
    echo "Commands:"
    echo "  install : Install the savemytpm tool"
    echo "  eve-9.3-recover : Verify TPM and disk certs, export disk key in cloud format for EVE 9.3"
    echo "  eve-9.3-export-key-plain : Export disk key in plain text format for EVE 9.3"
    exit 1
fi

if [ $1 = "install" ]; then
    apk add git go
    rm -rf ~/savemytpm-tpm/
    mkdir ~/savemytpm-tpm/
    chmod 777 ~/savemytpm-tpm/
    export TMPDIR=~/savemytpm-tpm
    cd ~/savemytpm-tpm
    git clone --depth 1 https://github.com/shjala/savemytpm.git
    cd savemytpm
    go build .
fi

if [ $1 = "eve-9.3-recover" ]; then
    devid=$(sha1sum /config/device.cert.pem | awk '{print $1 }')
    outfile=$PWD/$devid.disk-key-cloud.bin
    logfile=$PWD/recovertpm.log
    tarfile=$PWD/recovertpm-out.tar.gz
    cd ~/savemytpm-tpm/savemytpm

    echo "[+] Device ID: $devid" | tee -a $logfile
    echo "[+] Checking TPM and disk certs" | tee -a $logfile
    ./savemytpm --check-cert --cert-path "/config/device.cert.pem" --cert-index 0x817FFFFF >> $logfile 2>&1

    echo "[+] Test disk key availability... " | tee -a $logfile
        ./savemytpm --export-plain \
                --pub-index 0x1900000 --priv-index 0x1800000 --srk-index 0x81000002 \
                --pcr-hash sha1 --pcr-index "0, 1, 2, 3, 4, 6, 7, 8, 9, 13" >> $logfile 2>&1

    echo "[+] Exporting disk key in cloud format... " | tee -a $logfile
    ./savemytpm --export-cloud --output $outfile \
                --pub-index 0x1900000 --priv-index 0x1800000 --srk-index 0x81000002 \
                --ecdh-index 0x81000005 --cert-index 0x817FFFFF \
                --pcr-hash sha1 --pcr-index "0, 1, 2, 3, 4, 6, 7, 8, 9, 13" >> $logfile 2>&1

    tar -czvf $tarfile $outfile $logfile >> /dev/null 2>&1
    rm -f $outfile $logfile
    echo "[+] Done. Output archive recovertpm-out.tar.gz"
fi

if [ $1 = "eve-9.3-export-key-plain" ]; then
    devid=$(sha1sum /config/device.cert.pem | awk '{print $1 }')
    outfile=$PWD/$devid.disk-key-plain.bin
    echo "[+] Device ID: $devid"
    echo "[+] Output file: $outfile"
    cd ~/savemytpm-tpm/savemytpm
    ./savemytpm --export-plain --output $outfile \
                --pub-index 0x1900000 --priv-index 0x1800000 --srk-index 0x81000002 \
                --pcr-hash sha1 --pcr-index "0, 1, 2, 3, 4, 6, 7, 8, 9, 13"
fi
