import type { FindingItem, ASVSTestItem } from "./types";

export interface ExecutiveLapse {
  id: string;
  plainTitle: string;
  technicalName: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  iconType: "wifi" | "shield-alert" | "lock" | "globe" | "key" | "code" | "file-warning" | "alert-triangle";
  analogy: string;
  exploitScenario: string;
  businessImpact: string;
  actionForDev: string;
  technicalEvidence?: string;
  screenshot?: string | null;
  requirementIds?: string[];
}

interface ThreatProfile {
  plainTitle: string;
  iconType: ExecutiveLapse["iconType"];
  analogy: string;
  exploitScenario: string;
  businessImpact: string;
  defaultAction: string;
}

const THREAT_CATALOG: Record<string, ThreatProfile> = {
  hsts: {
    plainTitle: "Wi-Fi Snooping & Connection Downgrade",
    iconType: "wifi",
    analogy: "Like sending your bank letters in unsealed transparent envelopes instead of a locked vault pouch.",
    exploitScenario:
      "When customers use your website from an open public Wi-Fi network (like in a cafe, hotel, or airport), a nearby attacker can silently intercept the connection before it becomes secure. The attacker forces the browser onto unencrypted HTTP and reads passwords, login tokens, and payment details in plain text.",
    businessImpact: "Theft of customer account logins, financial details, and sensitive personal information.",
    defaultAction: "Tell your developers to enable the 'Strict-Transport-Security' (HSTS) response header with includeSubDomains.",
  },
  csp: {
    plainTitle: "Malicious Code Injection Shield Missing",
    iconType: "shield-alert",
    analogy: "Like leaving your building's master intercom unlocked so anyone can broadcast fake emergency orders.",
    exploitScenario:
      "If a hacker discovers any input field or public comment box on your website, they can inject hidden JavaScript. Because there is no Content-Security-Policy restriction in place, your visitors' browsers will blindly run that code, allowing attackers to steal session cookies, log keystrokes, or redirect visitors to phishing sites.",
    businessImpact: "Full account takeover, silent customer impersonation, brand defacement, and digital credit card skimming.",
    defaultAction: "Implement a restrictive 'Content-Security-Policy' (CSP) header specifying allowed script sources.",
  },
  clickjacking: {
    plainTitle: "Invisible Overlay & Click Trickery (Clickjacking)",
    iconType: "alert-triangle",
    analogy: "Like putting an invisible sheet over an official document so someone signs a check while thinking they are signing a birthday card.",
    exploitScenario:
      "An attacker builds a deceptive page (e.g. 'Click here to win a gift card') and loads your website inside an invisible, transparent window directly beneath the user's cursor. When the victim clicks the fake button, they are actually clicking an important button on your site (such as 'Delete Account' or 'Transfer Funds') without their consent.",
    businessImpact: "Users tricked into executing unauthorized transactions or changing account settings without their knowledge.",
    defaultAction: "Add the 'X-Frame-Options: DENY' (or 'SAMEORIGIN') header or CSP 'frame-ancestors' directive.",
  },
  mimesniff: {
    plainTitle: "Malicious File Disguise & Spoofing",
    iconType: "file-warning",
    analogy: "Like accepting a package marked 'Fresh Flowers' without checking that it actually contains a hidden recording device.",
    exploitScenario:
      "If your application allows users to upload files (such as avatars or resumes), an attacker can upload a malicious script disguised with a safe image extension. Without the nosniff protection, the visitor's browser tries to guess the content type and may execute it as code directly on their computer.",
    businessImpact: "Malware distribution to visitors and cross-site scripting vulnerabilities.",
    defaultAction: "Add the 'X-Content-Type-Options: nosniff' header to all HTTP and API responses.",
  },
  cors: {
    plainTitle: "Unrestricted Data Access by Foreign Websites",
    iconType: "globe",
    analogy: "Like leaving your internal office filing cabinets open with a sign saying 'Anyone from the street is welcome to copy files'.",
    exploitScenario:
      "Your server tells the entire internet that ANY third-party website is permitted to read its API responses. An attacker can host a booby-trapped website that quietly queries your backend in the background while your customer visits them, secretly downloading the customer's private profile or order history.",
    businessImpact: "Unauthorized extraction of proprietary business data and customer records by external websites.",
    defaultAction: "Restrict 'Access-Control-Allow-Origin' headers to trusted, explicitly approved domain names.",
  },
  cookie: {
    plainTitle: "Exposed Login & Session Keys",
    iconType: "key",
    analogy: "Like writing your master office keys on a sticky note pasted to the front desk window.",
    exploitScenario:
      "When users log in, your server assigns them a session cookie. If this cookie lacks security flags (HttpOnly and Secure), any third-party script running on the page can directly read the cookie. An attacker can copy this digital passkey and log in as that user indefinitely, bypassing multi-factor authentication.",
    businessImpact: "Direct account takeover and persistent impersonation of administrators or valued customers.",
    defaultAction: "Ensure all authentication cookies set the 'Secure', 'HttpOnly', and 'SameSite=Lax' (or 'Strict') attributes.",
  },
  tls: {
    plainTitle: "Unencrypted Public Connection (No HTTPS)",
    iconType: "lock",
    analogy: "Like shouting customer credit card numbers across a crowded room instead of speaking over an encrypted telephone line.",
    exploitScenario:
      "Your website serves content over unencrypted HTTP. Internet service providers, public Wi-Fi operators, and malicious actors along the network path can inspect, record, and even modify everything the user sees or submits on the page.",
    businessImpact: "Total loss of privacy and security; web browsers will display a stark 'NOT SECURE' warning to all visitors.",
    defaultAction: "Enforce HTTPS redirects across the entire domain and install a valid modern TLS certificate.",
  },
  referrer: {
    plainTitle: "Private Link & Token Leakage",
    iconType: "globe",
    analogy: "Like printing your private account number on the outer return address of every envelope you mail.",
    exploitScenario:
      "When visitors click external links on your website, their browser automatically reveals the full previous URL to the destination server. If your website puts password-reset codes, private usernames, or order IDs in the URL address bar, those secrets get leaked to third-party services.",
    businessImpact: "Accidental leakage of private URLs, customer identities, or reset tokens to external third parties.",
    defaultAction: "Add 'Referrer-Policy: strict-origin-when-cross-origin' to prevent URL parameter leakage.",
  },
  sri: {
    plainTitle: "Unverified Third-Party Code (Missing SRI)",
    iconType: "code",
    analogy: "Like installing software updates from an unverified public USB drive without checking if the file was modified.",
    exploitScenario:
      "Your website loads code libraries from external public hosting servers (CDNs). If that external CDN is ever breached by cybercriminals, they can replace the library with malware. Without Subresource Integrity hashes, your site will blindly execute the altered code on your customers' devices.",
    businessImpact: "Supply chain attacks affecting all visitors without modifying your own servers.",
    defaultAction: "Add cryptographic 'integrity' attributes and hashes to all external script and stylesheet tags.",
  },
  forms: {
    plainTitle: "Unprotected Form Submissions",
    iconType: "lock",
    analogy: "Like dropping confidential medical records into an unlocked cardboard bin on the sidewalk.",
    exploitScenario:
      "A web form on your site transmits user input across an unencrypted connection. When customers fill out their email, password, or contact information and press Submit, that data travels across the open internet unencrypted and readable by network snoops.",
    businessImpact: "Interception and theft of submitted customer passwords, emails, and personal messages.",
    defaultAction: "Ensure all form 'action' attributes use secure HTTPS endpoints.",
  },
  tabnabbing: {
    plainTitle: "Deceptive Tab Hijacking (Reverse Tabnabbing)",
    iconType: "alert-triangle",
    analogy: "Like stepping away from your desk for a moment and finding a fake impostor sitting in your chair when you look back.",
    exploitScenario:
      "When an external link opens in a new tab without protection, the destination page can quietly control the original tab in the background. While the user is browsing the new tab, the attacker replaces your original tab with a pixel-perfect fake login screen, tricking the user into re-entering their password.",
    businessImpact: "Phishing attacks deceiving returning users into surrendering their account credentials.",
    defaultAction: "Add rel='noopener noreferrer' to all outgoing links opening in new browser tabs.",
  },
  outdated_lib: {
    plainTitle: "Known Vulnerabilities in Software Libraries",
    iconType: "code",
    analogy: "Like using a known-flawed door lock that has master skeleton keys publicly shared on the internet.",
    exploitScenario:
      "Your website relies on outdated versions of open-source libraries that contain publicly known security bugs. Hackers don't need to invent new attacks—they can simply run off-the-shelf exploit scripts tailored to that exact version to compromise the application.",
    businessImpact: "Unpatched vulnerabilities exposing the website to known exploits and automated attack scripts.",
    defaultAction: "Audit and update client-side libraries and frontend dependencies to their latest stable releases.",
  },
};

function identifyCategory(text: string): string {
  const lower = text.toLowerCase();
  if (lower.includes("strict-transport-security") || lower.includes("hsts") || lower.includes("v3.4.1")) {
    return "hsts";
  }
  if (
    lower.includes("content-security-policy") ||
    lower.includes("csp") ||
    lower.includes("v3.4.2") ||
    lower.includes("v3.2.1") ||
    lower.includes("v3.4.7")
  ) {
    return "csp";
  }
  if (
    lower.includes("x-frame-options") ||
    lower.includes("clickjacking") ||
    lower.includes("frame-ancestors") ||
    lower.includes("v3.4.3") ||
    lower.includes("v3.4.6")
  ) {
    return "clickjacking";
  }
  if (lower.includes("x-content-type-options") || lower.includes("nosniff") || lower.includes("v4.1.1")) {
    return "mimesniff";
  }
  if (
    lower.includes("access-control-allow-origin") ||
    lower.includes("cors") ||
    lower.includes("wildcard") ||
    lower.includes("v4.3.1")
  ) {
    return "cors";
  }
  if (
    lower.includes("cookie") ||
    lower.includes("httponly") ||
    lower.includes("samesite") ||
    lower.includes("secure flag") ||
    lower.includes("v3.3.")
  ) {
    return "cookie";
  }
  if (lower.includes("tls") || lower.includes("https") || lower.includes("insecure connection") || lower.includes("v12.1.1")) {
    return "tls";
  }
  if (lower.includes("referrer") || lower.includes("v3.4.5")) {
    return "referrer";
  }
  if (lower.includes("subresource integrity") || lower.includes("sri") || lower.includes("integrity")) {
    return "sri";
  }
  if (lower.includes("form") || lower.includes("insecure form") || lower.includes("http://")) {
    return "forms";
  }
  if (lower.includes("tabnabbing") || lower.includes("noopener") || lower.includes("target=\"_blank\"")) {
    return "tabnabbing";
  }
  if (lower.includes("library") || lower.includes("jquery") || lower.includes("outdated") || lower.includes("version")) {
    return "outdated_lib";
  }
  return "generic";
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function translateFindingsToExecutiveLapses(
  findings: FindingItem[] = [],
  asvsResults: ASVSTestItem[] = []
): ExecutiveLapse[] {
  const lapsesByKey = new Map<string, ExecutiveLapse>();

  // 1. Process explicit findings first (curated by scanning agents)
  for (const f of findings) {
    const rawTitle = f.title || (f as unknown as Record<string, string>).detail || "Security Lapse";
    const categoryKey = identifyCategory(`${f.category || ""} ${rawTitle} ${f.evidence || ""}`);
    const profile = THREAT_CATALOG[categoryKey];

    const sev = (f.severity?.toLowerCase() || "medium") as ExecutiveLapse["severity"];
    const techEvidence = f.evidence || undefined;
    const action = f.remediation || (profile ? profile.defaultAction : "Review and resolve security issue.");

    if (!lapsesByKey.has(categoryKey)) {
      lapsesByKey.set(categoryKey, {
        id: `lapse-${categoryKey}`,
        plainTitle: profile ? profile.plainTitle : rawTitle,
        technicalName: rawTitle,
        severity: sev,
        iconType: profile ? profile.iconType : "alert-triangle",
        analogy: profile
          ? profile.analogy
          : "An automated security verification test flagged a non-standard configuration in this area.",
        exploitScenario: profile
          ? profile.exploitScenario
          : "An attacker could leverage this exposed configuration to bypass intended security controls or access unintended information.",
        businessImpact: profile
          ? profile.businessImpact
          : "Potential exposure or disruption depending on the nature of the application's sensitive data.",
        actionForDev: action,
        technicalEvidence: techEvidence,
        screenshot: f.screenshot || null,
        requirementIds: (f as unknown as Record<string, string[]>).requirement_ids || [],
      });
    } else {
      const existing = lapsesByKey.get(categoryKey)!;
      if (SEVERITY_WEIGHT[sev] > SEVERITY_WEIGHT[existing.severity]) {
        existing.severity = sev;
      }
      if (!existing.screenshot && f.screenshot) {
        existing.screenshot = f.screenshot;
      }
    }
  }

  // 2. Process failed ASVS results to catch any gaps not already captured
  for (const asvs of asvsResults) {
    if (asvs.status !== "FAIL") continue;

    const rawTitle = asvs.chapter_name || asvs.requirement_id || "ASVS Requirement";
    const categoryKey = identifyCategory(`${rawTitle} ${asvs.description || ""} ${asvs.evidence || ""}`);

    if (!lapsesByKey.has(categoryKey)) {
      const profile = THREAT_CATALOG[categoryKey];
      const sev = (asvs.severity?.toLowerCase() || "medium") as ExecutiveLapse["severity"];

      lapsesByKey.set(categoryKey, {
        id: `lapse-${categoryKey}`,
        plainTitle: profile ? profile.plainTitle : asvs.description || rawTitle,
        technicalName: `${asvs.requirement_id}: ${asvs.chapter_name}`,
        severity: sev,
        iconType: profile ? profile.iconType : "shield-alert",
        analogy: profile
          ? profile.analogy
          : "This control failed compliance against the international OWASP ASVS verification standard.",
        exploitScenario: profile
          ? profile.exploitScenario
          : "Without this defense-in-depth requirement verified, attackers have a wider attack surface to explore.",
        businessImpact: profile
          ? profile.businessImpact
          : "Non-compliance with OWASP ASVS Level 1 baseline security controls.",
        actionForDev: asvs.remediation || (profile ? profile.defaultAction : "Consult OWASP ASVS guidance."),
        technicalEvidence: asvs.evidence || undefined,
        screenshot: asvs.screenshot || null,
        requirementIds: [asvs.requirement_id],
      });
    } else {
      const existing = lapsesByKey.get(categoryKey)!;
      if (asvs.requirement_id && !existing.requirementIds?.includes(asvs.requirement_id)) {
        existing.requirementIds = [...(existing.requirementIds || []), asvs.requirement_id];
      }
    }
  }

  // Sort by severity (critical/high first)
  return Array.from(lapsesByKey.values()).sort(
    (a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0)
  );
}
