# 发行构建直接运行此官方镜像，不额外安装或升级系统软件包。
FROM docker.io/library/rust:1.99.1-bookworm@sha256:4715c3ad743951a3cea90e8b432f2a17e0ef5f3f3c3abf75108879e783b396f0 AS build
LABEL memoswish.rust="1.99.1" memoswish.glibc="2.36"

# 此阶段仅用于独立验证原生归档，不作为容器分发制品。
FROM docker.io/library/debian:bookworm-slim@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018 AS smoke
