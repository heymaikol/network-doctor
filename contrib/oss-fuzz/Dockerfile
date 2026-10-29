# Staged OSS-Fuzz configuration. Copy this directory into
# google/oss-fuzz/projects/network-doctor/ after acceptance.
FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/heymaikol/network-doctor.git "$SRC/network-doctor"
COPY build.sh "$SRC/build.sh"
WORKDIR "$SRC/network-doctor"
