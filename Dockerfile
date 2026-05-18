FROM gcr.io/distroless/base-debian13:nonroot@sha256:a557d784ac275c287d2bdf3172f47bece8d2a0ef3c0fdefb712e95084a04a562
ARG TARGETPLATFORM
ENTRYPOINT [ "/usr/bin/tunneller" ]
COPY $TARGETPLATFORM/tunneller /usr/bin/
