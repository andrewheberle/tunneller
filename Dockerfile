FROM gcr.io/distroless/base-debian13:nonroot@sha256:9039a88709bcc2bacf5a2faac331d65dd6840f763f225ad9594cc0c67bcd0fba
ARG TARGETPLATFORM
ENTRYPOINT [ "/usr/bin/tunneller" ]
COPY $TARGETPLATFORM/tunneller /usr/bin/
