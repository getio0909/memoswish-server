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
# daemon 监听所有容器接口，Compose 的宿主回环映射只限制经宿主端口的访问。
# single_user 会授予容器网络上所有可连接的未认证客户端所有者权限。
# 仅接入可信容器网络，或改用启用认证的 multi_tenant 模式。
ENV MEMOSWISH_BIND=0.0.0.0:8787 \
    MEMOSWISH_DATA_DIR=/var/lib/memoswish \
    RUST_LOG=info
VOLUME ["/var/lib/memoswish"]
EXPOSE 8787
ENTRYPOINT ["memoswishd"]
CMD ["serve"]
