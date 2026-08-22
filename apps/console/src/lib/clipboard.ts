/** Clipboard write with an execCommand fallback for browsers that reject the Clipboard API. */
export async function writeTextWithFallback(
  text: string,
  ports: {
    writeText?: (text: string) => Promise<void>
    execCommandCopy?: (text: string) => boolean
  }
): Promise<void> {
  if (ports.writeText !== undefined) {
    try {
      await ports.writeText(text)
      return
    } catch {
      // iOS and some in-app browsers reject Clipboard API.
    }
  }
  if (ports.execCommandCopy === undefined || !ports.execCommandCopy(text)) {
    throw new Error("copy-failed")
  }
}
