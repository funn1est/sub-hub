export function tomlString(text, key) {
  const match = text.match(new RegExp(`^${key} = "([^"]+)"`, "m"));
  if (!match) {
    throw new Error(`missing ${key}`);
  }
  return match[1];
}

export function tomlFlags(text) {
  const match = text.match(/compatibility_flags = \[([\s\S]*?)\]/);
  if (!match) {
    throw new Error("missing compatibility_flags");
  }
  return [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]);
}

export function conversionRuntimeFromToml(text) {
  return {
    compatibilityDate: tomlString(text, "compatibility_date"),
    compatibilityFlags: tomlFlags(text),
  };
}
