// 只检查名称，空值和新旧共存也拒绝；诊断不接触变量值。
function rejectLegacyEnvironment(environment = process.env) {
  for (const key of Object.keys(environment)) {
    if (!key.startsWith('LEARNTOK_')) continue;
    const suffix = key.slice('LEARNTOK_'.length);
    if (/^[A-Z0-9_]+$/.test(suffix)) {
      throw new Error(`Legacy environment variable LEARNTOK_${suffix} is unsupported. Use MEMOSWISH_${suffix}.`);
    }
    throw new Error('Legacy LEARNTOK_* environment variables are unsupported. Use MEMOSWISH_* replacements.');
  }
}
rejectLegacyEnvironment();
module.exports = rejectLegacyEnvironment;
