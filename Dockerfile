FROM gcr.io/distroless/base-debian13:nonroot@sha256:7fe4df6a4413adf5889960d345a28b4574aea0872ea47684c7244c8d88027dca
ARG TARGETPLATFORM
ENTRYPOINT [ "/usr/bin/tunneller" ]
COPY $TARGETPLATFORM/tunneller /usr/bin/
