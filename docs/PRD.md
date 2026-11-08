Veridion
Product Requirements Document (PRD)
HackMatrix '26 | AI-Powered Web Threat Detection & Digital Trust Intelligence
Version: 1.0
Status: Initial Draft
Product Type: Web-based Cybersecurity Platform
Project Stage: Hackathon MVP

1. PRODUCT OVERVIEW
1.1 Product Vision
Veridion is an intelligent web security and digital trust assessment platform designed to help users identify potentially malicious, fraudulent and impersonating websites before interacting with them.
The platform combines multiple layers of security analysis, including URL intelligence, domain characteristics, SSL/TLS certificate validation, website security configurations and collaborative threat intelligence.
Rather than simply classifying a website as safe or unsafe, Veridion aims to provide an evidence-backed assessment explaining why a website may or may not be trustworthy.
1.2 Problem Statement
The increasing sophistication of phishing websites, fraudulent payment portals, fake recruitment platforms and malicious redirects has made it difficult for ordinary internet users to distinguish legitimate websites from deceptive ones.
Existing security tools frequently operate independently, focusing on individual aspects of website security.
This creates a fragmented understanding of digital trust.
Users need an accessible platform that combines multiple security indicators into one understandable assessment while providing transparency into the findings.
1.3 Proposed Solution
Veridion will provide a unified interface where users can submit a website URL and receive a multi-layered security assessment.
The platform will:
Analyse suspicious URL and domain characteristics.
Check known threat intelligence sources.
Validate SSL/TLS certificates.
Assess observable website security configurations.
Examine suspicious redirect behaviour.
Generate an evidence-based risk assessment.
Allow users to report suspicious websites.

2. PRODUCT OBJECTIVES
The primary objectives are:
Build a functional multi-layered website threat detection system.
Integrate independent security analysis modules into one platform.
Develop an explainable risk assessment mechanism.
Make technical security findings understandable to non-technical users.
Introduce a collaborative mechanism for reporting suspicious websites.
Deliver a polished, accessible and demonstrable web application.
2.1 Key Differentiator
The defining feature of Veridion is its Explainable Digital Trust Assessment Engine.
Instead of relying entirely on external security APIs, the platform will combine independently generated technical findings with external threat intelligence.
Every risk classification should be accompanied by supporting evidence.
The product should answer three questions:
What did we detect?
Why does it matter?
What should the user do next?

3. TARGET USERS
User Category
Needs
General internet users
Verify suspicious links before interacting with them
Students and job seekers
Identify fraudulent recruitment and educational portals
Online shoppers
Assess potentially fraudulent shopping and payment websites
Small businesses
Understand basic website trust and security indicators
Security-conscious users
Access detailed technical analysis and threat information

The primary design audience will be non-technical users, with additional technical information available for advanced users.

4. CORE PRODUCT MODULES
MODULE 1: URL & DOMAIN INTELLIGENCE
Purpose: Identify suspicious URL and domain characteristics.
Functional Requirements
The system should:
Accept valid website URLs.
Parse domain names and URL components.
Detect unusually long or suspicious URLs.
Identify suspicious subdomain structures.
Detect IP-address-based URLs.
Identify suspicious characters and misleading URL patterns.
Detect potential typosquatting and lookalike domains.
Identify possible brand impersonation.
Proposed Implementation
Python URL parsing.
Domain normalization.
String similarity algorithms.
Punycode and homograph analysis.
DNS lookups.
Custom detection rules.
Expected Output
A structured report containing detected URL characteristics, suspicious patterns and relevant findings.

MODULE 2: THREAT REPUTATION ANALYSIS
Purpose: Determine whether a website has previously been associated with malicious activity.
Functional Requirements
The system should:
Check submitted URLs against available threat intelligence providers.
Identify known phishing and malware associations.
Retrieve available threat reputation information.
Display whether a URL has previously been reported.
Handle unavailable providers and API rate limits.
Potential Integrations
Google Safe Browsing.
PhishTank.
VirusTotal, subject to applicable usage restrictions.
Expected Output
A reputation assessment indicating whether the URL has known malicious associations.
Important: An absence of threat reports must not automatically classify a website as safe.

MODULE 3: SSL/TLS CERTIFICATE VALIDATION
Purpose: Evaluate the certificate-based security of a website.
Functional Requirements
The system should:
Establish a secure TLS connection where possible.
Retrieve certificate information.
Check certificate validity and expiry.
Verify hostname matching.
Retrieve issuer information.
Examine certificate chain validation.
Identify certificate-related warnings.
Proposed Implementation
Python SSL libraries.
Socket-based certificate inspection.
Optional SSL Labs integration.
Public certificate transparency information.
Expected Output
Certificate status, issuer, validity period, hostname verification and relevant warnings.
Important: A valid SSL/TLS certificate confirms certain aspects of encrypted communication and domain validation. It does not establish that a website or its operator is legitimate.

MODULE 4: WEBSITE SECURITY ASSESSMENT
Purpose: Identify observable security configuration weaknesses.
Functional Requirements
The system should:
Inspect HTTP response headers.
Identify missing recommended security headers.
Check HTTPS availability.
Identify insecure HTTP behaviour.
Examine redirect chains.
Detect suspicious redirect destinations.
Provide basic configuration recommendations.
Proposed Implementation
Python HTTPX.
Custom security-header inspection.
Controlled HTTP requests.
Expected Output
A list of detected configuration weaknesses and recommended improvements.
The platform must distinguish between security misconfiguration and confirmed malicious activity.

MODULE 5: RISK ASSESSMENT ENGINE
Purpose: Combine findings from individual analysis modules into a unified assessment.
This is the central intelligence component of Veridion.
Functional Requirements
The system should:
Collect structured outputs from all available analysis modules.
Assign appropriate severity to individual findings.
Calculate an overall risk score.
Generate a risk classification.
Account for missing or unavailable analysis results.
Provide confidence and evidence information.
Generate understandable recommendations.
Initial Risk Categories
Risk Score
Classification
0–24
Low Risk
25–49
Moderate Risk
50–74
High Risk
75–100
Critical Risk

These thresholds are provisional and should be calibrated through testing.
Proposed Initial Weight Distribution
Analysis Category
Weight
Threat reputation
30%
URL and domain intelligence
25%
Website behaviour
20%
Certificate assessment
15%
Security configuration
10%
Total
100%

The final scoring model must account for evidence quality, severity and confidence.
A confirmed phishing detection should trigger a strong warning rather than being diluted by otherwise positive indicators.
The system must also distinguish between:
Risk score: estimated level of threat.
Confidence: strength and completeness of the available evidence.

MODULE 6: COLLABORATIVE THREAT INTELLIGENCE
Purpose: Allow users to contribute to a shared database of suspicious websites.
Functional Requirements
The system should:
Allow users to submit suspicious URLs.
Store submitted reports.
Identify previously reported URLs.
Display available report information.
Maintain report timestamps.
Prevent duplicate submissions where possible.
Proposed Implementation
PostgreSQL / Supabase.
URL normalization.
Community report database.
Future Possibilities
User authentication.
Report verification.
Community reputation scores.
Historical threat tracking.
Threat trend visualisation.
For the initial MVP, community reporting can be implemented without introducing a complex user-account system.

5. USER EXPERIENCE & INTERFACE REQUIREMENTS
5.1 Main User Journey
User visits the Veridion homepage.
User enters a website URL.
Platform validates the submitted input.
User initiates a security scan.
Platform performs available analysis checks.
Results are combined by the risk assessment engine.
User receives a structured security report.
User can submit a community report if the website appears suspicious.
5.2 Required Pages
Page
Description
Priority
Landing Page
Product introduction and URL submission
P0
Scan Loading Page
Progress and analysis status
P0
Results Dashboard
Risk score and security findings
P0
Detailed Analysis
Individual module results and evidence
P0
Community Reports
View and submit suspicious URLs
P1
Scan History
Previously performed scans
P2
About / Methodology
Explain how Veridion works
P1

Priority classification:
P0: Essential for MVP.
P1: Important if development time permits.
P2: Future enhancement.
5.3 Dashboard Requirements
The results dashboard should display:
Submitted URL.
Overall risk score.
Risk classification.
Confidence indicator.
Individual analysis statuses.
Detected security issues.
Certificate information.
Threat intelligence findings.
Recommended actions.
The interface should prioritise clarity over excessive technical detail.
Advanced technical findings can be presented in expandable sections.

6. TECHNICAL REQUIREMENTS
6.1 Proposed Technology Stack
Component
Technology
Frontend
React.js
Build Tool
Vite
Styling
Tailwind CSS
Backend
Python + FastAPI
Database
PostgreSQL / Supabase
HTTP Requests
HTTPX
Domain Analysis
Python DNS libraries
Certificate Validation
Python SSL
Threat Intelligence
External security APIs
Deployment
Vercel + suitable backend hosting

The stack is provisional and may be adjusted according to team familiarity.
6.2 High-Level Architecture
Frontend Layer
React application responsible for user interaction, URL submission, scan progress and report visualisation.
↓
API Layer
FastAPI receives requests, validates inputs and manages communication between the frontend and backend modules.
↓
Analysis Layer
Independent modules perform:
URL and domain analysis.
Threat reputation lookup.
SSL/TLS validation.
Website security assessment.
Redirect inspection.
↓
Intelligence Layer
Risk assessment engine combines findings and generates the unified assessment.
↓
Data Layer
PostgreSQL stores community reports and, if implemented, scan history.
↓
Response Layer
Structured JSON response is returned to the frontend for visualisation.
6.3 API Design
Proposed endpoints:
Endpoint
Method
Purpose
/api/scan
POST
Initiate a website scan
/api/scan/{scan_id}
GET
Retrieve scan results
/api/report
POST
Submit a suspicious URL
/api/reports
GET
Retrieve community reports
/api/health
GET
Check backend availability

The initial implementation may use a synchronous scan endpoint. Asynchronous scan jobs can be introduced if execution time requires them.

7. NON-FUNCTIONAL REQUIREMENTS
7.1 Performance
The interface should remain responsive during scanning.
Independent analysis modules should execute concurrently where practical.
Every external request should have a timeout.
Failed providers should not crash the entire scan.
Scan progress should be communicated to users.
7.2 Security
Since Veridion processes potentially malicious URLs, backend security is essential.
Requirements:
Validate all submitted URLs.
Prevent server-side request forgery (SSRF).
Block requests to private, loopback and internal IP addresses.
Validate DNS resolutions and re-check resolved destinations.
Restrict redirect destinations and redirect counts.
Use request timeouts and response-size limits.
Keep API keys and secrets in backend environment variables.
Never expose sensitive scan credentials in frontend code.
Avoid executing submitted website scripts on the application server.
Use isolated infrastructure for any advanced browser-based analysis.
7.3 Reliability
Handle API rate limits.
Distinguish failed checks from clean checks.
Record unavailable analysis modules.
Avoid unsupported safe/unsafe classifications.
Preserve evidence supporting risk classifications.
7.4 Usability
Simple URL submission.
Clear visual hierarchy.
Understandable security explanations.
Responsive layout.
Accessible colour contrast.
Clear error and loading states.

8. MVP SCOPE
The hackathon MVP will focus on delivering a functional end-to-end scanning experience.
Must-Have Features
URL submission and validation.
Suspicious URL and domain analysis.
At least one functioning threat intelligence integration.
SSL/TLS certificate validation.
HTTP security-header assessment.
Unified risk assessment engine.
Evidence-backed results dashboard.
Safe handling of failed or unavailable checks.
Should-Have Features
Brand impersonation detection.
Redirect analysis.
Community threat reporting.
Certificate transparency lookup.
Detailed recommendations.
Stretch Features
Browser extension.
Historical threat tracking.
User authentication.
Advanced visual brand similarity detection.
Continuous domain monitoring.
AI-assisted natural-language security explanations.
Explicitly Out of Scope for the Initial MVP
Full penetration testing.
Exploitation of identified vulnerabilities.
Malware execution or reverse engineering.
Comprehensive vulnerability scanning.
Enterprise security monitoring.
Guaranteed identification of every phishing website.

9. TEAM STRUCTURE & RESPONSIBILITIES
The development team consists of four members.
Member
Designation
Responsibilities
You
Frontend Lead
UI/UX, design system, dashboard, frontend integration
C
Frontend Developer
Reusable components, scan interface, loading states, community UI
T
Backend Developer
FastAPI, API endpoints, database, third-party integrations
P
Security & Intelligence Developer
Detection logic, certificate checks, security assessment, risk scoring

Collaboration Requirements
Frontend members will agree on a shared component and response structure.
Backend and security members will agree on module interfaces.
All members will use the same GitHub repository.
Features should be developed on separate branches.
Changes should be reviewed before merging into the main branch.
Every member should understand the overall product architecture.

10. DEVELOPMENT ROADMAP
The following is a suggested sprint sequence, not a fixed calendar.
PHASE 1 — Foundation
Finalise project identity.
Create GitHub repository.
Set up frontend and backend environments.
Establish API response schema.
Build initial homepage and URL submission interface.
Deliverable: Running frontend and backend skeleton.
PHASE 2 — Core Development
Implement URL analysis.
Implement certificate validation.
Implement security-header checks.
Integrate a threat intelligence provider.
Build dashboard using mock responses.
Deliverable: Independently functioning analysis modules and frontend components.
PHASE 3 — Integration
Connect frontend and backend.
Implement risk scoring.
Combine analysis results.
Handle failed API calls.
Add evidence and recommendations.
Deliverable: Functional end-to-end scanner.
PHASE 4 — Differentiation
Implement lookalike domain detection.
Improve explainability.
Introduce community reporting if feasible.
Refine risk scoring.
Deliverable: Distinctive intelligence features.
PHASE 5 — Testing & Presentation
Test against legitimate and suspicious URLs.
Verify certificate and security findings.
Test failure scenarios.
Fix integration bugs.
Deploy the application.
Prepare the demonstration.
Deliverable: Stable, demonstrable hackathon MVP.

11. TESTING & ACCEPTANCE CRITERIA
The MVP will be considered functionally complete when the following conditions are satisfied.
Test
Expected Behaviour
Valid legitimate URL
Returns available analysis findings without automatically guaranteeing safety
Known phishing URL
Displays a strong warning when confirmed by a reputation source
Lookalike domain
Identifies suspicious domain similarity where applicable
Invalid URL
Returns a clear validation error
Expired certificate
Identifies certificate expiry
Hostname mismatch
Reports certificate hostname mismatch
Missing security headers
Identifies missing recommended headers
API unavailable
Marks the relevant check as unavailable
Previously reported URL
Displays existing community intelligence
Duplicate report
Prevents or identifies duplicate submissions
Unsafe network destination
Blocks the request

Testing must use controlled, non-sensitive test URLs and safe test environments.

12. SUCCESS METRICS
The project will be evaluated internally against the following objectives:
Functional completeness
Core analysis modules work independently.
Frontend and backend communicate successfully.
Results are generated through real analysis rather than hardcoded demonstrations.
Detection quality
Findings are supported by technical evidence.
False positives and false negatives are considered.
Missing data is not interpreted as proof of safety.
Explainability
Every major risk indicator has an understandable explanation.
Users can identify which findings influenced the assessment.
Product quality
The application is deployed and accessible.
The main user journey works without manual intervention.
The interface is coherent and responsive.
Technical differentiation
At least one original detection mechanism is implemented.
Multiple security layers contribute to one assessment.

13. RISKS & MITIGATION
Potential Risk
Mitigation
API rate limits
Use multiple eligible sources and local analysis
API downtime
Graceful failure handling
False positives
Evidence-based scoring and confidence indicators
False negatives
Clearly communicate detection limitations
Integration delays
Establish response schema early
SSRF vulnerabilities
Strict URL, DNS and network validation
Time constraints
Prioritise P0 features
Overengineering
Keep stretch features out of the initial sprint


14. FUTURE SCOPE
Beyond the hackathon, Veridion could evolve into a broader digital trust intelligence platform through:
Browser-based real-time protection.
Continuous domain and certificate monitoring.
Advanced brand impersonation detection.
Community-driven threat intelligence.
Historical threat analysis.
Organisation-specific monitoring.
More sophisticated machine-learning-based threat classification.

15. PRODUCT PRINCIPLE
Trust should be established through evidence, not appearance.
Veridion aims to make website security more transparent, accessible and understandable by bringing fragmented security indicators together into one explainable digital trust assessment.
Our goal is not simply to detect suspicious websites.
It is to help people understand the risks behind the websites they interact with every day.

Document Status: Version 1.0 — Initial Product Requirements
Project: Veridion | HackMatrix '26

