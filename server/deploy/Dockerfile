# memoswishd 多阶段构建。构建上下文为仓库根目录：
#   docker build -t memoswishd -f server/deploy/Dockerfile .
# 可选构建参数：
#   FEATURES=commercial-saas  构建商业版（需 --no-default-features，见下方逻辑）
#   WITH_ESPEAK=1             在运行镜像中安装 espeak-ng（真实人声 TTS）

FROM docker.io/library/rust:1-bookworm AS build
ARG FEATURES=""
WORKDIR /src/server
COPY server/ ./
COPY brand/ /src/brand/
RUN if [ -n "$FEATURES" ]; then \
      cargo build --release -p memoswishd --no-default-features --features "$FEATURES"; \
    else \
      cargo build --release -p memoswishd; \
    fi

FROM docker.io/library/debian:bookworm-slim
ARG WITH_ESPEAK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && if [ "$WITH_ESPEAK" = "1" ]; then apt-get install -y --no-install-recommends espeak-ng; fi \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /var/lib/memoswish memoswish \
 && mkdir -p /var/lib/memoswish && chown memoswish /var/lib/memoswish
COPY --from=build /src/server/target/release/memoswishd /usr/local/bin/memoswishd
USER memoswish
# 容器内监听网桥，由 Compose 将宿主端口限制到回环。
ENV MEMOSWISH_BIND=0.0.0.0:8787 \
    MEMOSWISH_DATA_DIR=/var/lib/memoswish \
    RUST_LOG=info
VOLUME ["/var/lib/memoswish"]
EXPOSE 8787
ENTRYPOINT ["memoswishd"]
CMD ["serve"]
