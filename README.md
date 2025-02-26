# Burparser Pro - Burp Suite Extension

## Overview
**Burparser Pro** is a powerful Burp Suite extension designed to extract and analyze directory structures, sensitive paths, and potential API endpoints from web application responses. The tool automates wordlist generation for fuzzing, aids in identifying access control issues, and provides a comprehensive overview of discovered endpoints.

## Features
- **Passive Directory Discovery**: Extracts and categorizes valid, forbidden, and redirected directories.
- **Wordlist Generation**: Builds a customized wordlist from observed paths, filenames, and parameters.
- **Enhanced Error Detection**: Identifies and classifies error pages to improve security testing.
- **Scope Filtering**: Option to process only in-scope URLs within Burp Suite.
- **Security Headers Extraction**: Analyzes headers for security misconfigurations.
- **Export Capabilities**: Supports exporting results and wordlists in JSON or text format.
- **Burp Suite Integration**: Provides an interactive UI within Burp Suite for easy navigation and analysis.

## Installation
1. Open **Burp Suite**.
2. Download the extension from the repository and then install it manually by navigating to `Extender` > `Extensions` > `Add`, selecting the downloaded file, and ensuring Jython is properly configured in `Extender` > `Options` > `Python Environment`.
3. Click `Install` or manually add the Jython script in `Extender` > `Extensions` > `Add`.
4. Ensure **Jython** is configured in `Extender` > `Options` > `Python Environment`.

## Usage
### 1. Extract Paths Automatically
- The extension passively processes HTTP responses and extracts directory paths, API endpoints, and sensitive URLs.
- Valid directories (200), Forbidden paths (403), Redirected URLs, and Error pages are categorized.

### 2. Generate Wordlists
- Extracted paths are compiled into a dynamic wordlist for use in fuzzing tools (e.g., `ffuf`, `dirsearch`).
- Click `Export Wordlist` to save a custom wordlist.

### 3. Manual Extraction from Site Map
- Right-click in the `Target` > `Site Map` and select **Extract Paths for Burparser**.
- Extract paths from selected nodes or entire subdirectories.

### 4. Filtering & Exporting
- Use the `Filter` field to search specific domains or paths.
- Click `Export Results` to save findings in JSON format.
- Export filtered wordlists with custom length and regex options.

## Requirements
- **Burp Suite** (Community or Professional Edition)
- **Jython** (Python 2.7 compatibility layer for Java)

## Contribution
Contributions are welcome! Submit a pull request or report issues via the **GitHub Issues** page.

## License
MIT License - Feel free to use, modify, and distribute.

## Contact
For support or feature requests, open an issue on the **GitHub repository**.

