# FileIntegrityChecker
#### Author: Bocaletto Luca

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge&logo=gnu)](LICENSE) [![Language: Python](https://img.shields.io/badge/Language-Python-blue?style=for-the-badge&logo=python)](https://www.python.org/) [![Linux-Compatible](https://img.shields.io/badge/Linux-Compatible-blue?style=for-the-badge&logo=linux)](https://www.kernel.org/) [![Status: Complete](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)](https://github.com/bocaletto-luca/Directory-Monitor)

FileIntegrityChecker is a Linux application written in Python with a Tkinter GUI that monitors critical files or entire directories by calculating and comparing their SHA256 hashes. By detecting any unauthorized modifications, it helps maintain file integrity and alerts you to changes. The project comes in two versions:
- **main_eng.py** – The English version.
- **main_ita.py** – The Italian version.
- **main_spanish.py** – The Spanish version.
- **main_french.py** – The French version.
- **main_portugues.py** – The Portugues version.
- **main_deutch.py** – The Deutch version.
- **main_chinese.py** – The Chinese version.
- **main_russian.py** – The Russina version.
- **main_arabe.py** – The Arabe version.
- **main_japanese.py** – The Japanese version.
- **main_hindi.py** – The Hindi version.
- **main_bengali.py** – The Bengali version.
- **main_korean.py** – The Korean version.
- **main_vietnamese.py** – The Vietnamese version.
- **main_turkish.py** – The Turkish version.
  
## Features

- **Directory Selection:**  
  Choose a directory to monitor for file integrity.

- **Recursive File Scanning:**  
  The tool scans the selected directory (recursively), ignoring certain system directories (e.g., `/proc`, `/sys`, `/dev`), and calculates the SHA256 hash of every file.

- **Initial State Storage:**  
  The initial set of file hashes is saved in a JSON file for later comparison.

- **Integrity Verification:**  
  Compare the current state of the directory with the saved state to detect file modifications, deletions, or new files. Visual notifications (via output messages and pop-up dialogs) alert you if any changes are found.

- **Scheduled Scans:**  
  Optionally, run periodic scans at a defined interval (e.g., every 60 seconds) with an easy “start”/“stop” mechanism.

- **Graphical User Interface:**  
  A clean and user-friendly interface built with Tkinter provides real-time status updates, a progress indicator, and area for detailed output.

- **Robust Logging:**  
  All operations and errors are logged in a file (`file_integrity_checker.log`) for troubleshooting and auditing.

## Requirements

- Python 3.x  
- Designed for Linux systems  
- No external dependencies; uses only standard Python libraries

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/bocaletto-luca/FileIntegrityChecker.git
   cd FileIntegrityChecker
   ```

2. **(Optional) Configuration:**  
   If needed, create or adjust the configuration file (if provided) to tailor default parameters.

## Usage

To run the **English version**:

```bash
python3 main_eng.py
```

To run the **Italian version**:

```bash
python3 main_ita.py
```

**Note:** It is recommended to run this tool with appropriate privileges (e.g., as root) so that access to all files is granted and the scanning results are complete.

## How It Works

The tool allows you to:
- Select a directory to monitor through the GUI.
- Calculate the initial SHA256 hashes of all files in the directory.
- Save the initial state to a JSON file.
- Manually verify file integrity by comparing the current state with the saved state.
- Optionally run scheduled scans to automatically check for changes at set intervals.
- Receive visual confirmations via the output area and message boxes if any modifications, removals, or new files are detected.

## Contributing

Contributions are welcome! If you find a bug, have suggestions, or want to enhance the tool further, please fork the repository and send us a pull request. You can also open an issue on the GitHub repository for any discussion.

## License

This project is licensed under the GNU General Public License (GPL). See the [LICENSE](LICENSE) file for details.

## Contact

For any questions, issues, or contributions, please open an issue on the [GitHub Issues page](https://github.com/bocaletto-luca/FileIntegrityChecker/issues) or contact me via email.

---

Happy Monitoring and Secure Coding!

---
