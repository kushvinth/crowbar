# crowbar - offline vulnerability intelligence (CLI + MCP server)
# Build: docker build -t crowbar .
# Run:   docker run --rm -v crowbar-data:/data crowbar doctor
#        (the index lives in the /data volume; build it once with `sync`+`build`)
FROM python:3.13-slim AS build
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.13-slim
LABEL org.opencontainers.image.source="https://github.com/kushvinth/crowbar"
LABEL org.opencontainers.image.description="Offline vulnerability intelligence for your terminal and your agent"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl /root/.cache
ENV CROWBAR_HOME=/data
VOLUME /data
ENTRYPOINT ["crowbar"]
CMD ["--help"]
