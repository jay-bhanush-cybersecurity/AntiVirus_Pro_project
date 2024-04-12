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
![Screenshot 2024-03-20 184501](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/e92cc93a-e628-4123-a6a9-3a45e2714d97)
---![Screenshot 2024-03-20 193207](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/d2ffe155-cd1f-4881-8067-831dcbf285cc)
![Screenshot 2024-03-20 193031](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/f659f548-30ca-42b8-9cae-d627798a399c)
![Screenshot 2024-03-20 193011](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/79b3065e-9522-4a62-a200-751456aa040c)
![Screenshot 2024-03-20 192624](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/55000811-5d8c-444a-aa4e-9415ad31da1d)
![Screenshot 2024-03-20 192156](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/88f0cf6e-38f9-4418-bf00-83efe34ae014)
![Screenshot 2024-03-20 192141](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/567530b9-f1ec-457d-ba02-770159abd41b)
![Screenshot 2024-03-20 191821](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/ccc7b00d-bf82-4fb7-be8a-25279240e6f3)
![Screenshot 2024-03-20 185314](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/d2a56c2b-50ac-4ea7-9b76-5117d1438743)
![Screenshot 2024-03-20 185236](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/668d6c8b-1c90-4848-a964-a51524099ef1)
![Screenshot 2024-03-20 193223](https://github.com/jay-bhanush-cybersecurity/AntiVirus_Pro_project/assets/159620262/b56050ed-d1e3-4982-a220-8c2782cf7f03)


### Conclusion <a name="conclusion"></a>

In conclusion, this project represents a significant contribution to cybersecurity, providing users with a robust antivirus solution. Moving forward, potential enhancements and extensions could further improve the application's effectiveness in combating evolving cyber threats.
