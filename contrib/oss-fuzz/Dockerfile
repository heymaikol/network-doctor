# Staged OSS-Fuzz configuration for google/oss-fuzz/projects/network-doctor/.
FROM gcr.io/oss-fuzz-base/base-builder-go
# Allows pre-merge testing of a proposal branch without merging to main.
ARG NETDOC_REF=main
RUN git clone --depth 1 https://github.com/heymaikol/network-doctor.git "$SRC/network-doctor" \
 && git -C "$SRC/network-doctor" fetch --depth 1 origin "$NETDOC_REF" \
 && git -C "$SRC/network-doctor" checkout --detach FETCH_HEAD
COPY build.sh "$SRC/build.sh"
WORKDIR "$SRC/network-doctor"
