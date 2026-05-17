FROM gcr.io/distroless/base-debian13:nonroot@sha256:a696c7c8545ba9b2b2807ee60b8538d049622f0addd85aee8cec3ec1910de1f9
ARG TARGETPLATFORM
ENTRYPOINT [ "/usr/bin/tunneller" ]
COPY $TARGETPLATFORM/tunneller /usr/bin/
