/**
 * Curated STRIDE → CWE / OWASP pointers for reports (no external DB dependency).
 * CWE IDs are from https://cwe.mitre.org/ — cite for triage, not legal guarantees.
 */
export const STRIDE_REFERENCE: Record<
  string,
  { summary: string; cwes: { id: string; name: string }[]; owasp: { label: string; url: string }[] }
> = {
  S: {
    summary: "Spoofing: attacks on identity and authenticity of actors, services, or messages.",
    cwes: [
      { id: "CWE-290", name: "Authentication Bypass by Spoofing" },
      { id: "CWE-346", name: "Origin Validation Error" },
    ],
    owasp: [
      { label: "OWASP Auth Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
    ],
  },
  T: {
    summary: "Tampering: unauthorized modification of data, code, or configuration.",
    cwes: [
      { id: "CWE-345", name: "Insufficient Verification of Data Authenticity" },
      { id: "CWE-472", name: "External Control of Assumed-Immutable Web Parameter" },
    ],
    owasp: [
      { label: "OWASP Data Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
    ],
  },
  R: {
    summary: "Repudiation: inability to prove who did what; logging and non-repudiation gaps.",
    cwes: [
      { id: "CWE-223", name: "Omission of Security-relevant Information" },
      { id: "CWE-778", name: "Insufficient Logging" },
    ],
    owasp: [
      { label: "OWASP Logging", url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html" },
    ],
  },
  I: {
    summary: "Information disclosure: exposure of sensitive data in transit, at rest, or via errors.",
    cwes: [
      { id: "CWE-200", name: "Exposure of Sensitive Information" },
      { id: "CWE-359", name: "Exposure of Private Personal Information" },
    ],
    owasp: [
      { label: "OWASP Top 10 A02", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
    ],
  },
  D: {
    summary: "Denial of service: availability attacks against resources, queues, or dependencies.",
    cwes: [
      { id: "CWE-400", name: "Uncontrolled Resource Consumption" },
      { id: "CWE-770", name: "Allocation of Resources Without Limits" },
    ],
    owasp: [
      { label: "OWASP DoS Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html" },
    ],
  },
  E: {
    summary: "Elevation of privilege: gaining capabilities beyond intended authorization.",
    cwes: [
      { id: "CWE-269", name: "Improper Privilege Management" },
      { id: "CWE-285", name: "Improper Authorization" },
    ],
    owasp: [
      { label: "OWASP Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
    ],
  },
};
