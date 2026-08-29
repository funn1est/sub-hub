import { writeTextWithFallback } from "./clipboard.ts"

export function writeClipboardInBrowser(text: string): Promise<void> {
  const clipboard = navigator.clipboard
  return writeTextWithFallback(text, {
    writeText:
      clipboard === undefined ? undefined : clipboard.writeText.bind(clipboard),
    execCommandCopy,
  })
}

export function readClipboardInBrowser(): Promise<string> {
  const clipboard = navigator.clipboard
  if (clipboard === undefined || clipboard.readText === undefined) {
    return Promise.reject(new Error("paste-failed"))
  }
  return clipboard.readText()
}

function execCommandCopy(text: string): boolean {
  const textarea = document.createElement("textarea")
  textarea.value = text
  textarea.setAttribute("readonly", "")
  textarea.style.position = "fixed"
  textarea.style.top = "0"
  textarea.style.left = "0"
  textarea.style.width = "1px"
  textarea.style.height = "1px"
  textarea.style.padding = "0"
  textarea.style.border = "none"
  textarea.style.opacity = "0"
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  textarea.setSelectionRange(0, text.length)
  try {
    return document.execCommand("copy")
  } finally {
    document.body.removeChild(textarea)
  }
}

export function saveFileInBrowser(file: {
  body: string
  mediaType: string
  filename: string
}): void {
  const blob = new Blob([file.body], { type: file.mediaType })
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = objectUrl
  link.download = file.filename
  link.rel = "noopener"
  link.style.display = "none"
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 2500)
}
