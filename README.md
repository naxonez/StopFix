# StopFix

**StopFix** is a browser extension designed to detect and report clipboard-based attacks such as *FileFix*, *ClickFix*, and similar malicious payloads. It works on any web page—including iframes—and alerts the user when suspicious content is copied to the clipboard. Users can review the content and choose to either ignore it or safely clear the clipboard.

## Features

- Detects suspicious clipboard activity triggered by web pages or iframes.
- Identifies PowerShell, mshta, msiexec, rundll32, regsvr32, and other common attack vectors.
- User-friendly modal warning with options to ignore or clear the clipboard.
- Site-agnostic: works across all domains without requiring page-specific integration.

## Installation (for development/testing)

1. Clone or download this repository.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** and select the folder of this project.

## Usage

- When a web page or iframe attempts to copy suspicious content to the clipboard, a modal will appear.
- Review the copied content in the modal.
- Choose **Ignore** to keep the clipboard intact, or **Clear** to remove the suspicious content.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## Detection Example
<img width="866" height="390" alt="image" src="https://github.com/user-attachments/assets/94f4a686-9a83-4b73-8e16-d4f1a65cc2b8" />
<img width="1004" height="551" alt="image" src="https://github.com/user-attachments/assets/77baf4c2-e9a9-4861-a168-227562a11baf" />
<img width="743" height="457" alt="image" src="https://github.com/user-attachments/assets/6f3aa98d-2df0-432d-a72b-42c62880fcbd" />



## License

MIT License
