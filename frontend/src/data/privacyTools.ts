export const privacyCategories = [
  "Password managers & credentials",
  "Two-factor authentication",
  "Private browsers & search",
  "Tracker & ad blocking",
  "VPN & secure DNS",
  "Encrypted communication & email",
  "Email aliases & address protection",
  "File encryption & metadata removal",
  "Privacy checks & account protection",
] as const;

export type PrivacyCategory = (typeof privacyCategories)[number];

export interface PrivacyTool {
  readonly name: string;
  readonly category: PrivacyCategory;
  readonly description: string;
  readonly bestFor: string;
  readonly url: `https://${string}`;
  readonly domain: string;
  readonly logo: `/privacy-tools/${string}`;
  readonly labels?: readonly ("Open source" | "Free" | "Freemium")[];
}

const localLogoPaths: Record<string, `/privacy-tools/${string}`> = {
  Bitwarden: "/privacy-tools/bitwarden.ico",
  KeePassXC: "/privacy-tools/keepassxc.ico",
  "Proton Pass": "/privacy-tools/proton-pass.ico",
  "2FAS": "/privacy-tools/2fas.ico",
  "Aegis Authenticator": "/privacy-tools/aegis.png",
  "Ente Auth": "/privacy-tools/ente-auth.png",
  Firefox: "/privacy-tools/firefox.ico",
  Brave: "/privacy-tools/brave.ico",
  "Tor Browser": "/privacy-tools/tor-browser.png",
  DuckDuckGo: "/privacy-tools/duckduckgo.ico",
  "uBlock Origin": "/privacy-tools/ublock-origin.png",
  "Privacy Badger": "/privacy-tools/privacy-badger.ico",
  ClearURLs: "/privacy-tools/clearurls.png",
  "Proton VPN": "/privacy-tools/proton-vpn.ico",
  "Mullvad VPN": "/privacy-tools/mullvad.ico",
  Quad9: "/privacy-tools/quad9.svg",
  NextDNS: "/privacy-tools/nextdns.ico",
  Signal: "/privacy-tools/signal.png",
  "Proton Mail": "/privacy-tools/proton-mail.ico",
  Tuta: "/privacy-tools/tuta.png",
  "SimpleX Chat": "/privacy-tools/simplex.ico",
  SimpleLogin: "/privacy-tools/simplelogin.ico",
  "Firefox Relay": "/privacy-tools/firefox-relay.svg",
  "addy.io": "/privacy-tools/addy.ico",
  VeraCrypt: "/privacy-tools/veracrypt.ico",
  Cryptomator: "/privacy-tools/cryptomator.ico",
  ExifTool: "/privacy-tools/exiftool.ico",
  MAT2: "/privacy-tools/mat2.png",
  "Have I Been Pwned": "/privacy-tools/hibp.ico",
  "Mozilla Monitor": "/privacy-tools/mozilla-monitor.ico",
  "EFF Cover Your Tracks": "/privacy-tools/eff-cover-your-tracks.ico",
  "Google Privacy Checkup": "/privacy-tools/google-privacy-checkup.png",
  JustDeleteMe: "/privacy-tools/justdeleteme.png",
};

const tool = (entry: Omit<PrivacyTool, "logo">): PrivacyTool => ({ ...entry, logo: localLogoPaths[entry.name] });

export const privacyTools: readonly PrivacyTool[] = [
  tool({ name: "Bitwarden", category: "Password managers & credentials", description: "Stores passwords and generates strong credentials.", bestFor: "Keeping account credentials in one encrypted vault.", url: "https://bitwarden.com/", domain: "bitwarden.com", labels: ["Open source", "Freemium"] }),
  tool({ name: "KeePassXC", category: "Password managers & credentials", description: "Keeps an encrypted password database under your local control.", bestFor: "Managing credentials without a hosted password vault.", url: "https://keepassxc.org/", domain: "keepassxc.org", labels: ["Open source", "Free"] }),
  tool({ name: "Proton Pass", category: "Password managers & credentials", description: "Password manager with password storage and email alias support.", bestFor: "Combining credential storage with supported email aliases.", url: "https://proton.me/pass", domain: "proton.me", labels: ["Freemium"] }),
  tool({ name: "2FAS", category: "Two-factor authentication", description: "Generates two-factor authentication codes.", bestFor: "Adding a second factor to supported accounts.", url: "https://2fas.com/", domain: "2fas.com", labels: ["Free"] }),
  tool({ name: "Aegis Authenticator", category: "Two-factor authentication", description: "Open-source authenticator for Android.", bestFor: "Keeping authentication codes on an Android device.", url: "https://getaegis.app/", domain: "getaegis.app", labels: ["Open source", "Free"] }),
  tool({ name: "Ente Auth", category: "Two-factor authentication", description: "Authenticator app with synchronization options.", bestFor: "Using authentication codes across supported devices.", url: "https://ente.io/auth/", domain: "ente.io", labels: ["Open source", "Free"] }),
  tool({ name: "Firefox", category: "Private browsers & search", description: "Web browser with privacy controls and tracking protection.", bestFor: "Adjusting browser privacy settings and tracker protection.", url: "https://www.mozilla.org/firefox/", domain: "mozilla.org", labels: ["Open source", "Free"] }),
  tool({ name: "Brave", category: "Private browsers & search", description: "Browser with built-in tracker and ad blocking features.", bestFor: "Browsing with built-in content blocking.", url: "https://brave.com/", domain: "brave.com", labels: ["Free"] }),
  tool({ name: "Tor Browser", category: "Private browsers & search", description: "Browser that routes traffic through the Tor network to improve anonymity.", bestFor: "Situations where Tor’s privacy model fits your needs.", url: "https://www.torproject.org/", domain: "torproject.org", labels: ["Open source", "Free"] }),
  tool({ name: "DuckDuckGo", category: "Private browsers & search", description: "Search engine focused on private searching.", bestFor: "Reducing personalized search profiling.", url: "https://duckduckgo.com/", domain: "duckduckgo.com", labels: ["Free"] }),
  tool({ name: "uBlock Origin", category: "Tracker & ad blocking", description: "Browser extension that blocks content and trackers.", bestFor: "Blocking unwanted web content in a supported browser.", url: "https://github.com/gorhill/uBlock", domain: "github.com", labels: ["Open source", "Free"] }),
  tool({ name: "Privacy Badger", category: "Tracker & ad blocking", description: "Learns to block certain third-party trackers.", bestFor: "Adding tracker blocking that adapts to browsing activity.", url: "https://privacybadger.org/", domain: "privacybadger.org", labels: ["Open source", "Free"] }),
  tool({ name: "ClearURLs", category: "Tracker & ad blocking", description: "Removes supported tracking parameters from web addresses.", bestFor: "Cleaning tracking parameters from links in supported browsers.", url: "https://github.com/ClearURLs/Addon", domain: "github.com", labels: ["Open source", "Free"] }),
  tool({ name: "Proton VPN", category: "VPN & secure DNS", description: "VPN service for routing internet traffic through a VPN connection.", bestFor: "Using a VPN service on supported devices.", url: "https://protonvpn.com/", domain: "protonvpn.com", labels: ["Freemium"] }),
  tool({ name: "Mullvad VPN", category: "VPN & secure DNS", description: "Privacy-oriented VPN service.", bestFor: "Choosing a VPN provider with a privacy-focused account model.", url: "https://mullvad.net/", domain: "mullvad.net" }),
  tool({ name: "Quad9", category: "VPN & secure DNS", description: "DNS service designed to block many known malicious domains.", bestFor: "Adding DNS-level blocking for known threats.", url: "https://quad9.net/", domain: "quad9.net", labels: ["Free"] }),
  tool({ name: "NextDNS", category: "VPN & secure DNS", description: "Configurable DNS filtering and protection service.", bestFor: "Controlling DNS filtering across devices.", url: "https://nextdns.io/", domain: "nextdns.io", labels: ["Freemium"] }),
  tool({ name: "Signal", category: "Encrypted communication & email", description: "End-to-end encrypted messaging and calls.", bestFor: "Private conversations with contacts who also use Signal.", url: "https://signal.org/", domain: "signal.org", labels: ["Open source", "Free"] }),
  tool({ name: "Proton Mail", category: "Encrypted communication & email", description: "Privacy-focused email service with encryption features.", bestFor: "Using a privacy-focused email provider.", url: "https://proton.me/mail", domain: "proton.me", labels: ["Freemium"] }),
  tool({ name: "Tuta", category: "Encrypted communication & email", description: "Email and calendar service with encryption features.", bestFor: "Using encrypted email and calendar services.", url: "https://tuta.com/", domain: "tuta.com", labels: ["Open source", "Freemium"] }),
  tool({ name: "SimpleX Chat", category: "Encrypted communication & email", description: "Messaging designed to minimize reliance on persistent user identifiers.", bestFor: "Messaging without a fixed user identifier.", url: "https://simplex.chat/", domain: "simplex.chat", labels: ["Open source", "Free"] }),
  tool({ name: "SimpleLogin", category: "Email aliases & address protection", description: "Creates email aliases that forward to a primary inbox.", bestFor: "Reducing exposure of a primary email address.", url: "https://simplelogin.io/", domain: "simplelogin.io", labels: ["Open source", "Freemium"] }),
  tool({ name: "Firefox Relay", category: "Email aliases & address protection", description: "Provides email masks and alias features.", bestFor: "Masking an email address when signing up for services.", url: "https://relay.firefox.com/", domain: "relay.firefox.com", labels: ["Freemium"] }),
  tool({ name: "addy.io", category: "Email aliases & address protection", description: "Email aliasing and forwarding service.", bestFor: "Creating separate aliases for different services.", url: "https://addy.io/", domain: "addy.io", labels: ["Open source", "Freemium"] }),
  tool({ name: "VeraCrypt", category: "File encryption & metadata removal", description: "Creates encrypted containers and volumes.", bestFor: "Encrypting local files or removable storage.", url: "https://veracrypt.fr/", domain: "veracrypt.fr", labels: ["Open source", "Free"] }),
  tool({ name: "Cryptomator", category: "File encryption & metadata removal", description: "Encrypts files before they are stored in cloud services.", bestFor: "Adding client-side encryption to cloud-stored files.", url: "https://cryptomator.org/", domain: "cryptomator.org", labels: ["Open source", "Freemium"] }),
  tool({ name: "ExifTool", category: "File encryption & metadata removal", description: "Inspects and edits metadata in supported files and images.", bestFor: "Reviewing or removing file metadata before sharing.", url: "https://exiftool.org/", domain: "exiftool.org", labels: ["Open source", "Free"] }),
  tool({ name: "MAT2", category: "File encryption & metadata removal", description: "Removes metadata from supported file formats.", bestFor: "Cleaning metadata from supported files before sharing.", url: "https://0xacab.org/jvoisin/mat2", domain: "0xacab.org", labels: ["Open source", "Free"] }),
  tool({ name: "Have I Been Pwned", category: "Privacy checks & account protection", description: "Checks whether an email address appears in known breach datasets.", bestFor: "Reviewing known breach exposure for an email address.", url: "https://haveibeenpwned.com/", domain: "haveibeenpwned.com", labels: ["Free"] }),
  tool({ name: "Mozilla Monitor", category: "Privacy checks & account protection", description: "Provides email-based breach exposure checks and guidance.", bestFor: "Checking reported breach exposure for an email address.", url: "https://monitor.mozilla.org/", domain: "monitor.mozilla.org", labels: ["Free"] }),
  tool({ name: "EFF Cover Your Tracks", category: "Privacy checks & account protection", description: "Tests browser tracking and fingerprinting characteristics.", bestFor: "Understanding how a browser appears to trackers.", url: "https://coveryourtracks.eff.org/", domain: "coveryourtracks.eff.org", labels: ["Free"] }),
  tool({ name: "Google Privacy Checkup", category: "Privacy checks & account protection", description: "Reviews privacy settings for a Google account.", bestFor: "Reviewing privacy settings for an existing Google account.", url: "https://myaccount.google.com/privacycheckup", domain: "myaccount.google.com", labels: ["Free"] }),
  tool({ name: "JustDeleteMe", category: "Privacy checks & account protection", description: "Lists account deletion guidance and links.", bestFor: "Finding deletion information for online services.", url: "https://justdeleteme.xyz/", domain: "justdeleteme.xyz", labels: ["Open source", "Free"] }),
];

export function filterPrivacyTools(tools: readonly PrivacyTool[], query: string, category: PrivacyCategory | "All tools") {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  return tools.filter((item) => {
    const inCategory = category === "All tools" || item.category === category;
    const searchable = `${item.name} ${item.category} ${item.description} ${item.bestFor}`.toLocaleLowerCase();
    return inCategory && (!normalizedQuery || searchable.includes(normalizedQuery));
  });
}
