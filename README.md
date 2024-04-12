### Antivirus Application with PyQt5

This project is an antivirus application developed using PyQt5, integrating YARA rules and hashing algorithms for malware detection and scanning. The application provides a user-friendly graphical interface for scanning directories, system files, PDF documents, registry keys, and archives.

---

### Table of Contents

1. [Introduction](#introduction)
2. [Project Overview](#project-overview)
3. [Implementation Details](#implementation-details)
4. [Features](#features)
5. [Demonstration](#demonstration)
6. [Conclusion](#conclusion)

---

### Introduction <a name="introduction"></a>

The project aims to develop a robust antivirus application to enhance cybersecurity measures. Antivirus software is crucial in protecting systems from various cyber threats. We utilized PyQt5 for the GUI, threading for scanning operations, YARA rules for malware detection, and hashing algorithms for file integrity verification.

---

### Project Overview <a name="project-overview"></a>

The project's code structure consists of key components:

- **AntivirusGUI:** Main window for the antivirus application, designed using PyQt5 for the graphical interface.
- **ScannerThread:** A threading class to handle scanning operations without freezing the GUI.
- **Antivirus class:** Core functionality for the antivirus, including signature loading, file scanning, and hash computation.

---

### Implementation Details <a name="implementation-details"></a>

We leveraged several libraries and functionalities:

- **PyQt5 Widgets:** Used for creating interactive GUI elements.
- **Threading:** Implemented to perform scanning operations in the background.
- **Hashing Algorithms:** Used for computing file hashes to detect tampering.
- **YARA Rules:** Integrated for efficient malware detection based on predefined rules.

---

### Features <a name="features"></a>

The antivirus application offers the following features:

- **Directory Scanning:** Scan specific directories for potential threats.
- **Deep System Files Scanning:** Thoroughly inspect system files for hidden malware.
- **PDF Document Scanning:** Detect malicious content within PDF files.
- **Registry Scanning:** Identify malware embedded within system registries.
- **Archive Scanning:** Comprehensive inspection of archived files.
- **Export Detailed Scan Reports:** Export detailed reports with scan results for analysis.

---

### Demonstration <a name="demonstration"></a>

We will demonstrate the live functionality of the antivirus application:

- Showcasing how to scan directories, PDF documents, and archives.
- Exporting detailed scan reports for further analysis.

---

### Conclusion <a name="conclusion"></a>

In conclusion, this project represents a significant contribution to cybersecurity, providing users with a robust antivirus solution. Moving forward, potential enhancements and extensions could further improve the application's effectiveness in combating evolving cyber threats.
