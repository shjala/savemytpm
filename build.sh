# quick and dirty build script
docker run -v $(pwd):/home/tpmsaver --rm -it --platform linux/amd64 alpine \
       sh -c "apk add go && cd /home/tpmsaver && go build -o savemytpm.amd64"

docker run -v $(pwd):/home/tpmsaver --rm -it --platform linux/arm64 alpine \
       sh -c "apk add go && cd /home/tpmsaver && go build -o savemytpm.arm64"

mv -f savemytpm.amd64 pre-built/
mv -f savemytpm.arm64 pre-built/

