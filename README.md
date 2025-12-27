# IDOR Hunter – Universal Behavioral Analyzer

IDOR Hunter is a Burp Suite extension designed to assist with identifying **potential horizontal Insecure Direct Object Reference (IDOR)** issues using **behavioral analysis**.

The extension passively observes normal Burp traffic, performs a single safe mutation of detected object identifiers, and highlights requests where the application response changes without an obvious access control failure.

This project is currently under active development and is intended as a **testing assistant**, not an automated exploitation tool.

---

## ✨ Key Features

- Assists with detecting horizontal IDOR candidates
- Works with a single authenticated session
- Supports query parameters such as:
  - `id`
  - `user_id`
  - `processor_id`
  - any `*_id` numeric parameter
- Numeric ID detection (2–7 digits)
- Parameter-aware mutation (no blind replacement)
- Behavioral response comparison (content fingerprinting)
- Works with HTML and JSON responses
- Safe by default (single mutation per request)
- Dedicated Burp tab with request/response inspection
- Export findings in JSON format

---

## 🚀 How to Use

### 1. Load the Extension in Burp Suite

1. Open **Burp Suite**
2. Navigate to **Extender → Extensions**
3. Click **Add**
4. Set **Extension type** to `Python`
5. Select the `idor_hunter.py` file
6. Confirm the extension loads successfully:



A new tab named **IDOR Hunter** will appear in Burp.

---

### 2. Use the Application Normally

The extension works **passively** and requires no configuration.

- Browse the target application through Burp
- Interact with the application as a normal user
- Send requests via **Proxy**, **Repeater**, or **Scanner**

No manual triggering is required.

---

### 3. Automatic ID Mutation and Analysis

When the extension observes a request containing a numeric object identifier (for example `id`, `user_id`, or `*_id`):

- A single, safe mutation of the identifier is generated
- The mutated request is replayed using the same session and headers
- The original and mutated responses are compared using behavioral fingerprinting

If a behavioral difference is detected without an access control failure, the request is surfaced as a candidate for manual review.

---

### 4. Review Detected Candidates

1. Open the **IDOR Hunter** tab
2. Detected candidates appear in a table showing:
- Request URL
- Parameter name
- Original identifier value
- Mutated identifier value
- Estimated severity

3. Select a row to inspect:
- The mutated request
- The corresponding response

All findings should be **manually verified** before reporting.

---

### 5. Export Findings (Optional)

- Click **Export Findings (JSON)**
- Findings are printed to the Burp output console in JSON format
- Useful for reporting or further analysis

---

## 🧠 Use Cases

- Assisting IDOR testing when only one user account is available
- Identifying IDOR candidates in REST APIs
- Testing admin panels and internal applications
- Supporting authorization testing in modern SPAs where data is loaded via API calls
- Reducing manual effort when reviewing large volumes of traffic

---

## ⚠️ Important Notes & Limitations

- The extension does **not automatically confirm vulnerabilities**
- Some valid IDORs may not produce observable response differences
- UI-only or workflow-based IDORs may not be detected
- Manual verification is always required
- The tool is intended to **assist**, not replace, manual authorization testing

---

## 🔐 Safety Considerations

- Only one mutation is performed per request
- No authentication headers are modified
- No brute-force behavior
- Destructive endpoints (e.g. delete, logout, payment) are excluded by design

---

## 📄 Disclaimer

This extension is intended for use on systems you own or are explicitly authorized to test.  
It is provided for educational and research purposes only.

---

## 📌 Project Status

This project is actively being built and refined to better understand where automation can realistically assist IDOR testing in modern application architectures.
