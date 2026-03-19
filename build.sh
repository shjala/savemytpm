# quick and dirty build script
docker run -v $(pwd):/home/tpmsaver --rm -it --platform linux/amd64 alpine \
       sh -c "apk add go && cd /home/tpmsaver && go build -o flex-pcr-test.amd64"

docker run -v $(pwd):/home/tpmsaver --rm -it --platform linux/arm64 alpine \
       sh -c "apk add go && cd /home/tpmsaver && go build -o flex-pcr-test.arm64"

mv -f flex-pcr-test.amd64 pre-built/
mv -f flex-pcr-test.arm64 pre-built/

