# SQL Injection Tester

A Python-based SQL injection testing tool with a modern web interface. This tool helps identify potential SQL injection vulnerabilities in web applications.

## Features

- Modern, user-friendly web interface
- Support for both GET and POST requests
- Customizable parameters
- Multiple SQL injection payloads
- Real-time testing results
- Responsive design

## Installation

1. Clone the repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Enter the target URL and configure the test:
   - Select HTTP method (GET or POST)
   - Add parameters if needed
   - Click "Test for SQL Injection"

4. View the results in the table below

## Security Note

This tool is for educational and testing purposes only. Always:
- Get proper authorization before testing any website
- Use it only on systems you own or have permission to test
- Be aware of local laws and regulations regarding security testing

## Disclaimer

The developers of this tool are not responsible for any misuse or damage caused by this program. Use it responsibly and ethically. 