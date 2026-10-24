FROM gcr.io/distroless/base-debian13:nonroot@sha256:f9518b74815721f537a7458cc693b4406208c04fce23bbffab511516117f34fd
ARG TARGETPLATFORM
ENTRYPOINT [ "/usr/bin/tunneller" ]
COPY $TARGETPLATFORM/tunneller /usr/bin/
