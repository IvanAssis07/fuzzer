FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 https://github.com/IvanAssis07/fuzzer smaz     # or use other version control
WORKDIR smaz
COPY build.sh $SRC/
