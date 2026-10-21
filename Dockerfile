# crowbar - offline vulnerability intelligence (CLI + MCP server)
# Build: docker build -t crowbar .
# Run:   docker run --rm -v crowbar-data:/data crowbar doctor
#        (the index lives in the /data volume; build it once with `sync`+`build`)
FROM python:3.13-slim@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f AS build
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir --require-hashes -r packaging/docker/build-requirements.txt \
 && python -m build --wheel --no-isolation --outdir /dist

FROM python:3.13-slim@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f
LABEL org.opencontainers.image.source="https://github.com/kushvinth/crowbar"
LABEL org.opencontainers.image.description="Offline vulnerability intelligence for your terminal and your agent"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl /root/.cache
ENV CROWBAR_HOME=/data
VOLUME /data
ENTRYPOINT ["crowbar"]
CMD ["--help"]
