// Display helper — strip the internal "-ec2" deployment suffix so the UI
// shows plain scanner names. The DB value (e.g. "checkov-ec2") is left
// untouched; this is cosmetic only.
export function formatScannerName(source) {
  if (!source || typeof source !== 'string') return source
  return source.replace(/-ec2$/, '')
}

// Same spirit for free-text messages (agent traces, toasts, etc.) — strips
// "-ec2" anywhere in the string. Collapses the double-spaces that leaves
// behind so copy stays readable.
export function stripEc2(text) {
  if (!text || typeof text !== 'string') return text
  return text.replace(/-ec2\b/g, '').replace(/\s{2,}/g, ' ')
}
