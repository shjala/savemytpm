#!/bin/sh

if [ ! -f savemytpm ]; then
    arch=$(arch)
    if [ "$arch" = 'x86_64' ]; then 
        wget https://github.com/shjala/savemytpm/raw/main/out/savemytpm.amd64 > /dev/null 2>&1
        mv savemytpm.amd64 savemytpm
        chmod +x savemytpm
    elif [ "$arch" = 'aarch64' ]; then
        wget https://github.com/shjala/savemytpm/raw/main/out/savemytpm.arm64 > /dev/null 2>&1
        mv savemytpm.arm64 savemytpm
        chmod +x savemytpm
    fi
fi

if [ $# -eq 0 ]; then
    echo "Usage: run.sh <command>"
    echo "Commands:"
    echo "  eve-9.3-recover : Verify TPM and disk certs, export disk key in encrypted cloud format for EVE 9.3"
    echo "  eve-9.3-export-key-plain : Export disk key in plain text format for EVE 9.3"
    exit 1
fi

if [ $1 = "eve-9.3-recover" ]; then
    devid=$(sha1sum /config/device.cert.pem | awk '{print $1 }')
    outfile=$PWD/disk-key-encrypted-cloud
    logfile=$PWD/recovertpm.log
    tarfile=$PWD/recovertpm-out-id.$devid.tar.gz

    echo "[+] Device ID: $devid" | tee -a $logfile
    echo "[+] Checking TPM and disk certs" | tee -a $logfile
    ./savemytpm --check-cert --cert-path "/config/device.cert.pem" --cert-index 0x817FFFFF 2>&1 | tee -a $logfile

    echo "[+] Test disk key availability... " | tee -a $logfile
        ./savemytpm --export-plain \
                --pub-index 0x1900000 --priv-index 0x1800000 --srk-index 0x81000002 \
                --pcr-hash sha1 --pcr-index "0, 1, 2, 3, 4, 6, 7, 8, 9, 13" 2>&1 | tee -a $logfile

    echo "[+] Exporting disk key in cloud format... " | tee -a $logfile
    ./savemytpm --export-cloud --output $outfile \
                --pub-index 0x1900000 --priv-index 0x1800000 --srk-index 0x81000002 \
                --ecdh-index 0x81000005 --cert-index 0x817FFFFF \
                --pcr-hash sha1 --pcr-index "0, 1, 2, 3, 4, 6, 7, 8, 9, 13" 2>&1 | tee -a $logfile

    tar -czvf $tarfile $logfile $outfile* >> /dev/null 2>&1
    rm -f $outfile* $logfile
    echo "[+] Done. Output archive $tarfile"
fi

if [ $1 = "eve-9.3-export-key-plain" ]; then
    devid=$(sha1sum /config/device.cert.pem | awk '{print $1 }')
    outfile=$PWD/disk-key-plain.id.$devid.bin
    echo "[+] Device ID: $devid"
    echo "[+] Output file: $outfile"
    ./savemytpm --export-plain --output $outfile \
                --pub-index 0x1900000 --priv-index 0x1800000 --srk-index 0x81000002 \
                --pcr-hash sha1 --pcr-index "0, 1, 2, 3, 4, 6, 7, 8, 9, 13"
fi
