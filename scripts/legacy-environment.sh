# 仅在当前入口检查导出的旧名称，不读取或输出变量值。
for legacy_environment_key in "${!LEARNTOK_@}"; do
  legacy_environment_suffix=${legacy_environment_key#LEARNTOK_}
  if [[ $legacy_environment_suffix =~ ^[A-Z0-9_]+$ ]]; then
    printf 'Legacy environment variable LEARNTOK_%s is unsupported. Use MEMOSWISH_%s.\n' "$legacy_environment_suffix" "$legacy_environment_suffix" >&2
  else
    printf 'Legacy LEARNTOK_* environment variables are unsupported. Use MEMOSWISH_* replacements.\n' >&2
  fi
  exit 1
done
unset legacy_environment_key legacy_environment_suffix
