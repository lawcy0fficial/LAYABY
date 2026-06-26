# 🐛 Bug Bounty Writeups — 2026 Curated Index
> Publicly disclosed reports from HackerOne, Bugcrowd, Intigriti & researcher blogs.
> All links are public. Always test only on authorized targets within program scope.

---

## 📋 Table of Contents
1. [Live Writeup Databases](#-live-writeup-databases)
2. [IDOR / BOLA](#-idor--bola)
3. [SSRF](#-ssrf)
4. [XSS — Stored, Reflected, DOM](#-xss)
5. [Account Takeover (ATO) Chains](#-account-takeover-chains)
6. [Authentication & Authorization Bypass](#-auth-bypass)
7. [RCE & SSTI](#-rce--ssti)
8. [Business Logic & Race Conditions](#-business-logic--race-conditions)
9. [API Security — GraphQL, REST, Mass Assignment](#-api-security)
10. [OAuth & JWT Attacks](#-oauth--jwt)
11. [Subdomain Takeover & Cloud Misconfig](#-subdomain-takeover--cloud-misconfig)
12. [Prompt Injection / AI Bugs (2026 New Class)](#-prompt-injection--ai-bugs-2026)
13. [Chained / Multi-Bug Reports](#-chained-multi-bug-reports)
14. [GitHub Repos — Aggregated Writeup Collections](#-github-repos)
15. [Where to Find New Writeups Daily](#-where-to-find-new-writeups-daily)

---

## 🔴 Live Writeup Databases

| Platform | URL | What You Get |
|---|---|---|
| HackerOne Hacktivity | https://hackerone.com/hacktivity | Disclosed reports, filter by type/bounty/program |
| Bugcrowd Disclosed | https://bugcrowd.com/programs (→ Disclosed Submissions) | Real triage-accepted reports |
| Intigriti Blog | https://blog.intigriti.com | Monthly challenge writeups + researcher stories |
| Pentester Land | https://pentester.land/writeups | 10,000+ writeups, filterable by bug type, program, bounty |
| BugBoard | https://bugboard.rsecloud.com/hackerone_reports | Searchable HackerOne disclosed reports |
| HackerOne Disclosed Archive | https://github.com/ajaysenr/HackerOne-Disclosed-Reports | 9,583 reports auto-updated, filter by severity/CWE/year |
| InfoSec Writeups | https://infosecwriteups.com | Daily community writeups on Medium |
| OpenBugBounty | https://www.openbugbounty.org | XSS-focused, thousands of reports, no login needed |
| Writeups.io | https://writeups.io | Crowdsourced reviews + writeup links |
| BugBountyHunter Disclosed | https://www.bugbountyhunter.com/disclosed | HackerOne sorted by vulnerability type |

---

## 🔵 IDOR / BOLA

| Title | Program | Bounty | Link |
|---|---|---|---|
| IDOR at Reddit GraphQL — change any user's profile links | Reddit (H1) | $5,000 | https://infosecwriteups.com/how-these-idor-vulnerability-earned-5000-hackerone-reddit-bug-bounty-c685fcfbd8bc |
| IDOR allows viewing other users' private invoices | HackerOne (generic) | — | https://hackerone.com/hacktivity (search: IDOR invoice) |
| Delete any video via IDOR — Facebook | Facebook | $6,300 | https://hackerone.com/hacktivity (search: Facebook video IDOR) |
| Access private DMs via IDOR — Twitter | Twitter | $2,940 | https://hackerone.com/hacktivity (search: Twitter DM IDOR) |
| Any user can view all trips of any driver — Uber | Uber | $10,000 | https://hackerone.com/hacktivity (search: Uber driver trips IDOR) |
| IDOR → account takeover (3–4 bugs in one hunt) | Redacted | — | https://infosecwriteups.com/gone-in-a-click-idor-vulnerabilities-in-image-upload-function-6c4817b44d8c |
| IDOR that allowed takeover of any user account | Redacted | — | https://infosecwriteups.com/idor-that-allowed-me-to-takeover-any-users-account-129e55871d8 |
| UUIDv1 IDOR — predicting sequential UUIDs | Various | $1,000s | https://infosecwriteups.com/my-complete-bug-bounty-hunting-workflow-every-command-i-use-step-by-step-68484276471f |
| How I Escalated Privileges in a File-Sharing Platform by Changing One Parameter | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| From an Informational Finding to a Valuable Lesson: My IDOR Discovery | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| GUID IDOR amplification — leak GUIDs then use in IDOR | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| Build an IDOR Vulnerability Lab: Why WHERE Clauses Don't Protect | Educational | — | https://github.com/rix4uni/medium-writeups (search title) |

**Pattern to hunt:** `GET /api/v1/user/{id}/resource` → change `{id}` → check if server returns another user's data without auth check.

---

## 🟠 SSRF

| Title | Program | Bounty | Link |
|---|---|---|---|
| SSRF → AWS metadata ($4,913) via 303 redirect bypass | Redacted | $4,913 | https://medium.com/techfenix/ssrf-server-side-request-forgery-worth-4913-my-highest-bounty-ever-7d733bb368cb |
| SSRF in image proxy → AWS metadata | Redacted (H1 #341876) | $6,000 | https://hackerone.com/reports/341876 |
| Blind SSRF via webhook — Shopify | Shopify | $25,000 | https://hackerone.com/hacktivity (search: Shopify webhook SSRF) |
| SSRF to RCE via PDF generation — Confluence | Atlassian | $12,500 | https://hackerone.com/hacktivity (search: Confluence PDF SSRF) |
| GitHub Actions SSRF via webhook URL | GitHub | — | https://hackerone.com/hacktivity (search: GitHub Actions SSRF) |
| Top 25 SSRF Bug Bounty Reports (collection) | Various | Various | https://corneacristian.medium.com/top-25-server-side-request-forgery-ssrf-bug-bounty-reports-136928356eca |
| AWS CloudGoat EC2_SSRF Lab Walkthrough | Lab/Educational | — | https://github.com/rix4uni/medium-writeups (search title) |
| SSRF via ffmpeg processing — Vimeo | Vimeo | — | https://hackerone.com/hacktivity (search: Vimeo ffmpeg SSRF) |
| Blind SSRF via Sentry misconfiguration | Redacted | — | https://hackerone.com/hacktivity (search: Sentry SSRF) |
| API Bug Bounty — SSRF via webhook?url= | Various | $10k+ | https://medium.com/@manojxshrestha/api-bug-bounty-mastery-2026-hunt-hidden-endpoints-to-land-10k-payouts-957832efc29c |

**Pattern to hunt:** Any parameter accepting a URL — `?url=`, `?webhook=`, `?callback=`, `?redirect=`, image import, PDF generator, export feature.

---

## 🟡 XSS

| Title | Program | Bounty | Link |
|---|---|---|---|
| Intigriti May 2026 Challenge: XSS via Stored Payload & SCA Shield bypass | Intigriti | — | https://github.com/rix4uni/medium-writeups (search title) |
| XSS in user display name → session cookie theft (Stored) | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| DOM XSS via innerHTML sink — location.search source | PortSwigger Lab | — | https://github.com/rix4uni/medium-writeups (search: DOM XSS innerHTML) |
| How I found XSS on Admin page without login | Redacted | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| XSS in ConnectWise Remote Access Platform | ConnectWise | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Reflected XSS on a major German website | Redacted | — | https://github.com/rix4uni/medium-writeups (search: Reflected XSS German) |
| Beyond alert(1): Advanced XSS Payload Crafting & Filter Bypasses 2026 | Educational | — | https://github.com/rix4uni/medium-writeups (search title) |
| CVE-2025–65640: Escalating a Stored XSS to Account Takeover | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| Wormable XSS on Rarible NFT Marketplace | Rarible | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| XSS Intigriti challenge solution | Intigriti | — | https://infosecwriteups.com/xss-intigriti-challenge-dae2dba1cb4c |
| Bypassing XSS Filters — Techniques and Solutions | Educational | — | https://infosecwriteups.com/bypassing-xss-filters-techniques-and-solutions-d6674029f1e9 |
| From False Positive to Hall of Fame: Web Cache Poisoning via XSS | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |

**Pattern to hunt:** Every input field, URL parameter, HTTP header reflection — especially profile fields, search boxes, error messages, import/export features.

---

## 🔴 Account Takeover Chains

| Title | Program | Bounty | Link |
|---|---|---|---|
| Full ATO — a tale of two bugs | Redacted | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| ATO via CSRF → email change → password reset | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| Exploiting Password Reset Poisoning for ATO + max bounty | Various | Max | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| CSRF to account takeover | Redacted | — | https://bugreader.com/_imjitendra_@account-takeover-via-csrf-260 |
| Shopify ATO — HackerOne Ambassador World Cup finding | Shopify | — | https://ophionsecurity.com/blog/shopify-acount-takeover |
| A walk-through of a High-severity cross-company ATO | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| The MFA Bypass That Wasn't an MFA Problem: Broken Auth lesson | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| Chaining Open Redirect with XSS to Account Takeover | Redacted | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| IDOR that allowed me to takeover any user's account | Redacted | — | https://infosecwriteups.com/idor-that-allowed-me-to-takeover-any-users-account-129e55871d8 |
| $500,000 Prompt: How an AI-Driven Hack Penetrated Google's systems | Google | $500,000 | https://github.com/rix4uni/medium-writeups (search title) |

**Pattern to hunt:** Password reset flow → Host header injection, CSRF on email-change, OAuth redirect_uri open redirect leaking auth code via Referer.

---

## 🟣 Auth Bypass

| Title | Program | Bounty | Link |
|---|---|---|---|
| GitLab Auth Bypass — password reset token not expiring | GitLab | $12,000 | https://hackerone.com/hacktivity (search: GitLab reset token) |
| Dropbox 2FA Bypass — backup code reuse | Dropbox | $4,913 | https://hackerone.com/hacktivity (search: Dropbox 2FA) |
| HackerOne Auth Bypass — predictable JWT secret | HackerOne | — | https://hackerone.com/hacktivity (search: HackerOne JWT) |
| SAML response not validated — authenticate as admin | Redacted | — | https://hackerone.com/reports/812064 |
| Bypassing Intel DCM auth via Kerberos/LDAP spoofing (CVE-2022-33942) | Intel | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| I Tried Logging In… and Accidentally Did Responsible Disclosure | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| PortSwigger: Information Disclosure → Authentication bypass via inference | Lab | — | https://github.com/rix4uni/medium-writeups (search: PortSwigger auth bypass) |
| From Revoked Privileges to Resource Creation: Privilege Persistence | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |

---

## 🔴 RCE & SSTI

| Title | Program | Bounty | Link |
|---|---|---|---|
| Top 25 RCE Bug Bounty Reports (collection) | Various | Various | https://corneacristian.medium.com/top-25-rce-bug-bounty-reports-bc9555cca7bc |
| RCE via file upload — stop redirect in /admin/* to bypass auth | Ubiquiti | — | https://hackerone.com/hacktivity (search: Ubiquiti file upload RCE) |
| RCE via Flask/Jinja template injection (SSTI) | Redacted | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Exploitation of FOSSBilling Server-Side Template Injection | FOSSBilling | — | https://github.com/rix4uni/medium-writeups (search title) |
| Chaining Blind SSRF to get RCE | Redacted | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| How I Escalated a Time-Based SQLi to RCE | Redacted | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| RCE on AEM instance without JAVA knowledge | Adobe | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Dell KACE K1000 Remote Code Execution | Dell | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Anatomy of a Full Compromise: Info Disclosure → RCE | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| Exploiting Log Poisoning (LFI→RCE) | Redacted | — | https://github.com/rix4uni/medium-writeups (search: Log Poisoning) |
| TryHackMe Include walkthrough: SSRF, log poisoning & LFI2RCE | Lab | — | https://github.com/rix4uni/medium-writeups (search title) |
| RCE on CS:GO client via unsanitized entity ID | Valve | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Apache Tomcat CVE-2025-24813 — deserialization RCE | Apache | — | https://github.com/0xMarcio/cve |

---

## 🟤 Business Logic & Race Conditions

| Title | Program | Bounty | Link |
|---|---|---|---|
| Race condition → double-spend in payment flow | Various | $10k+ | https://medium.com/@tanjimul_islam/backend-mastery-the-real-bug-bounty-superpower-2026-guide-0141f8e271de |
| Coupon stacking exploit — price manipulation | Fintech | $10k+ | https://medium.com/@tanjimul_islam/backend-mastery-the-real-bug-bounty-superpower-2026-guide-0141f8e271de |
| Negative value in quantity field → credit generation | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| File Size Restriction Bypass via MAX_FILE_SIZE param manipulation | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| Workflow bypass — skip payment step in multi-step checkout | Various | — | https://medium.com/@tanjimul_islam/backend-mastery-the-real-bug-bounty-superpower-2026-guide-0141f8e271de |
| Excessive Data Exposure → access to paid features free | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| Web/Mobile Business Logic Vulnerabilities example | Educational | — | https://github.com/rix4uni/medium-writeups (search: Business Logic) |
| I Opened a Settings Page… and Found Everyone's Personal Data | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |

**Pattern to hunt:** Parallel requests on any state-changing action (buy, redeem, vote), negative/zero/decimal values in numeric fields, skipping steps in multi-stage flows.

---

## 🔵 API Security

| Title | Program | Bounty | Link |
|---|---|---|---|
| API Bug Bounty Mastery 2026 — Hidden Endpoints to $10k+ | Educational | — | https://medium.com/@manojxshrestha/api-bug-bounty-mastery-2026-hunt-hidden-endpoints-to-land-10k-payouts-957832efc29c |
| GraphQL introspection enabled → full schema exposed | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| Mass assignment — adding `role=admin` to registration | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| API v1 still alive after v2 launch — unprotected endpoints | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| X-Internal-Service header trusted blindly → privilege escalation | Various | — | https://medium.com/@tanjimul_islam/backend-mastery-the-real-bug-bounty-superpower-2026-guide-0141f8e271de |
| Mobile app uses older API version — lower security maturity | Various | — | https://github.com/shuvonsec/claude-bug-bounty/blob/main/skills/bug-bounty/SKILL.md |
| Exposed .env file → credentials → full access | Various | — | https://infosecwriteups.com/my-complete-bug-bounty-hunting-workflow-every-command-i-use-step-by-step-68484276471f |
| JS file leaking API keys and internal endpoints | Various | — | https://infosecwriteups.com/my-complete-bug-bounty-hunting-workflow-every-command-i-use-step-by-step-68484276471f |
| Exposed .git/config on production server | Various | — | https://infosecwriteups.com/my-complete-bug-bounty-hunting-workflow-every-command-i-use-step-by-step-68484276471f |
| GraphQL batching → rate limit bypass | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |

---

## 🟢 OAuth & JWT

| Title | Program | Bounty | Link |
|---|---|---|---|
| OAuth redirect_uri open redirect → auth code theft via Referer | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| JWT algorithm confusion — RS256 → HS256 with public key | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| JWT `none` algorithm accepted — forge admin token | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| JWT secret predictable — HackerOne program | HackerOne | — | https://hackerone.com/hacktivity (search: JWT secret) |
| OAuth CSRF → account linking hijack | Various | — | https://hackerone.com/hacktivity (search: OAuth CSRF) |
| Open redirect in OAuth flow leaking access token | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |

---

## 🌐 Subdomain Takeover & Cloud Misconfig

| Title | Program | Bounty | Link |
|---|---|---|---|
| Subdomain Takeover — unclaimed S3 bucket | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| Exposed Google Maps API Key on a Global Brand's website | Redacted | — | https://github.com/rix4uni/medium-writeups (search title) |
| Leaked AWS credentials → S3/EC2 access | Various | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| AWS CloudGoat EC2_SSRF → metadata → takeover | Lab | — | https://github.com/rix4uni/medium-writeups (search: CloudGoat EC2) |
| A Simple Supply Chain Bug — $11,850 — GitLab trust in open source | GitLab | $11,850 | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Bore-dom, IP Pools, and a Nation's Water Control: How I Breached | Gov | — | https://github.com/rix4uni/medium-writeups (search title) |
| I Found a Vulnerability on a Government Web Portal | Gov | — | https://github.com/rix4uni/medium-writeups (search title) |
| Passive Vulnerability Assessment of a Government Enterprise Web App | Gov | — | https://github.com/rix4uni/medium-writeups (search title) |

---

## 🤖 Prompt Injection / AI Bugs (2026)

> Fastest growing bug class in 2026. HackerOne reports prompt injection up 540% YoY.

| Title | Program | Bounty | Link |
|---|---|---|---|
| $500,000 Prompt: How an AI-Driven Hack Penetrated Google's systems | Google | $500,000 | https://github.com/rix4uni/medium-writeups (search title) |
| The Lethal Trifecta: AI Agents with Tool Access + Prompt Injection | Educational | — | https://github.com/rix4uni/medium-writeups (search title) |
| The Hidden Bugs in Your LLM: Why AI Systems Fail in Ways You Never Expect | Educational | — | https://github.com/rix4uni/medium-writeups (search title) |
| AI and Pentesting: The Silent Revolution Redefining Security | Educational | — | https://github.com/rix4uni/medium-writeups (search title) |
| Chatbot IDOR — accessing other users' conversation history | Various | — | https://github.com/shuvonsec/claude-bug-bounty/blob/main/skills/bug-bounty/SKILL.md |
| System prompt extraction via direct injection | Various | — | https://github.com/shuvonsec/claude-bug-bounty/blob/main/skills/bug-bounty/SKILL.md |
| Indirect prompt injection via uploaded document → data exfil | Various | — | https://github.com/shuvonsec/claude-bug-bounty/blob/main/skills/bug-bounty/SKILL.md |

**Where to hunt:** Any AI chatbot, document summarizer, code reviewer, email AI assistant, agent with tool access.

---

## 🔗 Chained Multi-Bug Reports

> These are the highest-paying finds — combining 2+ low/medium bugs into Critical.

| Title | Chain | Bounty | Link |
|---|---|---|---|
| SSRF → RCE via PDF generation | SSRF + LFR + RCE | $12,500 | https://hackerone.com/hacktivity |
| Blind SSRF → RCE | SSRF + internal service | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| SQLi → RCE escalation | Time-based SQLi + OS command | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Open Redirect → XSS → ATO | 3-bug chain | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| CSRF → email change → password reset → ATO | 3-step ATO | — | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| GUID leak + IDOR → full user data access | Info disclosure + IDOR | High | https://github.com/The-XSS-Rat/SecurityTesting/blob/master/Checklists/2026-bug-bounty-guide.md |
| SSRF → AWS metadata → credentials → S3 takeover | 4-step chain | Critical | https://infosecwriteups.com/my-complete-bug-bounty-hunting-workflow-every-command-i-use-step-by-step-68484276471f |
| XSS + CSRF → stored XSS account takeover | 2-bug chain | — | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| Information disclosure → RCE → full compromise | 3-step chain | — | https://github.com/rix4uni/medium-writeups (search: Anatomy Full Compromise) |

---

## 📦 GitHub Repos — Aggregated Writeup Collections

| Repo | Description | URL |
|---|---|---|
| ajaysenr/HackerOne-Disclosed-Reports | 9,583 H1 reports, auto-updated daily, filter by year/CVE/severity | https://github.com/ajaysenr/HackerOne-Disclosed-Reports |
| devanshbatham/Awesome-Bugbounty-Writeups | Bug-type-wise curated writeup list | https://github.com/devanshbatham/Awesome-Bugbounty-Writeups |
| ngalongc/bug-bounty-reference | Classic reference list of writeups by type | https://github.com/ngalongc/bug-bounty-reference |
| fardeen-ahmed/Bug-bounty-Writeups | Large collection inc. chained bugs | https://github.com/fardeen-ahmed/Bug-bounty-Writeups |
| insecrez/Bug-bounty-Writeups | Community maintained writeup links | https://github.com/insecrez/Bug-bounty-Writeups |
| rix4uni/medium-writeups | Auto-updated every 10 min from Medium | https://github.com/rix4uni/medium-writeups |
| reddelexc/hackerone-reports | Top H1 reports ranked by votes/bounty | https://github.com/reddelexc/hackerone-reports |
| 0xMarcio/cve | Latest CVEs with public PoC links | https://github.com/0xMarcio/cve |

---

## 📡 Where to Find New Writeups Daily

```
HackerOne Hacktivity    → hackerone.com/hacktivity
  Filter: Disclosed → Sort by Bounty → Type: Critical/High

Pentester Land          → pentester.land/writeups
  Sort by: Added Date (newest first)

InfoSec Writeups        → infosecwriteups.com
  Daily community writeups on Medium

Intigriti Blog          → blog.intigriti.com
  Monthly challenge solutions + researcher posts

PortSwigger Research    → portswigger.net/research
  Deep technical web security research

Assetnote Blog          → blog.assetnote.io
  High-quality chain attack writeups (Shubham Shah)

Twitter/X Follows:
  @NahamSec   @TomNomNom   @jobertabma   @SecurityMB
  @zseano     @stokfredrik  @hacker_

Medium Search Queries:
  "bug bounty writeup 2026"
  "hackerone report $10000"
  "bug bounty account takeover 2026"
  "SSRF writeup bounty"
```

---

## 📌 2026 What's Paying Most

| Rank | Bug Class | Avg Payout | Why |
|---|---|---|---|
| 1 | AI / Prompt Injection | $10k–$500k | New surface, few hunters, high impact |
| 2 | Auth Bypass Chains | $10k–$50k | Business impact clear |
| 3 | SSRF → Cloud Metadata | $5k–$25k | AWS/GCP creds = critical |
| 4 | Race Conditions (payments) | $5k–$30k | Direct financial impact |
| 5 | IDOR on sensitive data | $1k–$15k | Privacy impact, GDPR multiplier |
| 6 | RCE (SSTI/deserialization) | $5k–$50k | Always critical |
| 7 | OAuth/JWT flaws | $2k–$15k | ATO potential |
| 8 | Subdomain Takeover | $500–$5k | Easy to prove |

> 💡 **Pro tip:** Read 5–10 disclosed reports per day in one bug class.
> After 30 days you'll recognize the pattern instantly on new targets.
