export const threatActivity = [
  { day: "Mon", scans: 42 },
  { day: "Tue", scans: 68 },
  { day: "Wed", scans: 57 },
  { day: "Thu", scans: 91 },
  { day: "Fri", scans: 74 },
  { day: "Sat", scans: 113 },
  { day: "Sun", scans: 88 },
];

export const threatDistribution = [
  { name: "Phishing", value: 42 },
  { name: "Financial Scam", value: 27 },
  { name: "OTP Scam", value: 16 },
  { name: "Account Takeover", value: 9 },
  { name: "Other", value: 6 },
];

export const recentScans = [
  {
    id: "SC-001",
    title: "Bank KYC Message",
    type: "Message",
    score: 94,
    confidence: 96,
    status: "critical" as const,
    date: "Today, 10:41 PM",
  },
  {
    id: "SC-002",
    title: "Secure Login Verification",
    type: "URL",
    score: 86,
    confidence: 91,
    status: "high" as const,
    date: "Today, 9:14 PM",
  },
  {
    id: "SC-003",
    title: "College Notice",
    type: "Screenshot",
    score: 11,
    confidence: 98,
    status: "safe" as const,
    date: "Today, 6:32 PM",
  },
  {
    id: "SC-004",
    title: "Courier Delivery Link",
    type: "URL",
    score: 63,
    confidence: 87,
    status: "high" as const,
    date: "Yesterday, 8:11 PM",
  },
  {
    id: "SC-005",
    title: "UPI Payment Request",
    type: "Message",
    score: 51,
    confidence: 82,
    status: "medium" as const,
    date: "Yesterday, 4:37 PM",
  },
];

export const sampleThreat = {
  score: 94,
  confidence: 96,
  type: "Banking Phishing",
  title: "Potential KYC phishing attempt",
  indicators: [
    {
      title: "Urgency language",
      detail: "The message pressures the recipient to act immediately.",
      severity: "high" as const,
    },
    {
      title: "Bank impersonation",
      detail: "The wording attempts to represent a financial institution.",
      severity: "high" as const,
    },
    {
      title: "Credential request",
      detail: "The content asks the user to complete a verification process.",
      severity: "critical" as const,
    },
    {
      title: "Suspicious URL",
      detail: "The destination does not clearly match the claimed organization.",
      severity: "critical" as const,
    },
  ],
};