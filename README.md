# 🐍 Python Vulnerability Scanner (VS Code Prototype)

A Visual Studio Code extension (under development) designed to detect security vulnerabilities in Python code.

## 🎯 Objective

Perform static security analysis focusing on the OWASP Top 10 (specifically A03:2021-Injection, A06:2021-Vulnerable and Outdated Components, and A09:2021-Security Logging and Monitoring Failures).

## ✨ Key Features

This scanner goes beyond simple text matching by implementing advanced static analysis techniques:

* **AST Analysis:** Code is transformed into an **Abstract Syntax Tree (AST)**, allowing for a deep and precise analysis of the code's structure and logic.
* **Taint Analysis:** The engine tracks the flow of untrusted data (**Sources**, e.g., `request.args.get`) to dangerous functions (**Sinks**, e.g., `cursor.execute`).
* **Contextual Detection:** The engine identifies **Sanitizers** (e.g., `shlex.quote` or `int()`) that "clean" the data, significantly reducing false positives.
* **Confidence Classification:** Detected vulnerabilities are classified based on the analysis depth:
    * **HIGH Confidence:** Confirmed by Taint Analysis (user data directly reaches a dangerous sink).
    * **LOW Confidence:** Dangerous patterns detected, but data flow could not be fully confirmed (requires manual review).

## 🛡️ Detected Vulnerabilities

### Injection_analyzer
* **SQL Injection:** `cursor.execute(f"...")`
* **Command Injection:** `os.system(...)`, `subprocess.run(...)`
* **Code Injection:** `eval()`, `exec()`
* **LDAP Injection:** `ldap.search_s(f"...")`
* **NoSQL Injection:** `db.users.find({"$where": "..."})`
* **Template Injection (SSTI):** `Template(f"...")`
* **XML / XXE Injection:** `ET.fromstring(...)`
* **XPath Injection:** `root.xpath(f"...")`
* **Header Injection (CRLF):** `response.headers['...'] = ...`
* **Log Injection:** `logging.error(f"...")`

### Logging_analyzer
* Missing Security Logging
* Sensitive Data in Logs
* Inappropriate Log Level
* Unlogged Exceptions

## ⚙️ How It Works (Development Notes)

The core scanner logic (`scanner.py`) operates in a two-phase process:

1.  **Phase 1: Pattern Detection (BaseAnalyzers)**
    * The user's Python code is parsed into an AST using `ast.parse`.
    * A series of "Visitors" (e.g., `SQLInjectionAnalyzer`) traverses the tree looking for **Sinks** called with dangerous patterns (e.g., f-strings or direct variables).
    * A list of "potential issues" is generated.

2.  **Phase 2: Refinement with Taint Analysis (TaintAnalyzer)**
    * A second visitor traverses the tree to track data flow.
    * **Sources:** Identifies untrusted data inputs and "taints" the receiving variables.
    * **Sanitizers:** Identifies functions that neutralize risks. If a "tainted" variable passes through a sanitizer, it is marked as "clean".

## 🚀 Project Status & Roadmap

* **Week 1:** Initial setup and AST research.
* **Week 2:** Research and study on Injection vulnerabilities.
* **Week 3:** Pattern analysis prototype (`BaseAnalyzers`) for SQLi and Command Injection.
* **Week 4:** Implementation of the **Taint Analysis** engine and expansion to 10 injection classes (A03).
* **Week 5:** Refinement of Taint Analysis (Sanitizers) and confidence logic. FP/FN correction.
* **Week 6:** Study on Security Logging and Monitoring Failures and initial prototype.
* **Week 7:** `logging_analyzer` refinement.
* **Week 8 (Current):** `dependency_analyzer` development.


