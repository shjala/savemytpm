apk add git go
rm -rf ~/savemytpm-tpm/
mkdir ~/savemytpm-tpm/
chmod 777 ~/savemytpm-tpm/
export TMPDIR=~/savemytpm-tpm
cd ~/savemytpm-tpm
git clone --depth 1 https://github.com/shjala/savemytpm.git
cd savemytpm
go build .
./savemytpm --index 0x1900000
