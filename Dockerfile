# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# python:3.12-slim-bookworm (multi-platform index)
FROM python@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS build
# ghcr.io/astral-sh/uv:0.12.19 (multi-platform index)
COPY --from=ghcr.io/astral-sh/uv@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 /uv /usr/local/bin/uv
WORKDIR /opt/chainsaw-mcp
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable
RUN .venv/bin/chainsaw-mcp-bootstrap --dest /opt/chainsaw-mcp/vendor/chainsaw
ADD --checksum=sha256:fa376e837cc2ebb830a0d59d1e6ab2adf60a2a85b1c2c71594bc3f41d6810aee \
    https://codeload.github.com/WithSecureLabs/chainsaw/tar.gz/refs/tags/v2.16.5 \
    /opt/chainsaw-source.tar.gz

# python:3.12-slim-bookworm (same index as the build stage)
FROM python@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS runtime
LABEL org.opencontainers.image.title="chainsaw-mcp" \
      org.opencontainers.image.source="https://github.com/MadameFabulous/chainsaw-mcp"
WORKDIR /opt/chainsaw-mcp
ENV PATH="/opt/chainsaw-mcp/.venv/bin:/opt/chainsaw-mcp/vendor/chainsaw:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CHAINSAW_HOME=/opt/chainsaw-mcp \
    CHAINSAW_EVIDENCE_ROOTS=/evidence \
    CHAINSAW_OUTPUT_DIR=/data/results \
    CHAINSAW_CUSTOM_RULES_DIR=/data/custom-rules \
    CHAINSAW_UPLOAD_DIR=/data/uploads \
    MCP_TRANSPORT=streamable-http MCP_HOST=0.0.0.0 MCP_PORT=18098 MCP_PATH=/mcp
COPY --from=build /opt/chainsaw-mcp/.venv ./.venv
COPY --from=build /opt/chainsaw-mcp/vendor ./vendor
COPY LICENSE /usr/share/licenses/chainsaw-mcp/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/licenses/chainsaw-mcp/THIRD_PARTY_NOTICES.md
COPY --from=build /opt/chainsaw-source.tar.gz /usr/share/licenses/chainsaw/source-v2.16.5.tar.gz
COPY scripts/mcp-health.py ./healthcheck.py
RUN groupadd --gid 10001 chainsaw \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /data chainsaw \
    && mkdir -p /data/results /data/custom-rules /evidence \
    && chown -R 10001:10001 /data
USER 10001:10001
EXPOSE 18098
HEALTHCHECK --interval=30s --timeout=15s --start-period=20s --retries=3 \
    CMD ["python", "/opt/chainsaw-mcp/healthcheck.py", "--attempts", "1"]
ENTRYPOINT ["chainsaw-mcp"]
