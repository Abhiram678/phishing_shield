# Phishing Shield 🛡️

Phishing Shield is an advanced web application that analyzes URLs for potential phishing threats. It provides detailed security insights to help users identify and avoid malicious websites.

![Phishing Shield Preview](https://via.placeholder.com/800x400?text=Phishing+Shield+Screenshot)

## Features

- **Comprehensive URL Analysis**: Examines URL structure, domain age, TLD risk, and more
- **Domain Reputation Checking**: Verifies domain registration details and history
- **SSL Certificate Validation**: Checks for proper implementation of HTTPS
- **Visual Risk Assessment**: Clear indicators with detailed explanations
- **Security Recommendations**: Customized security advice based on analysis results
- **Technical Details**: In-depth information including WHOIS data, IP addresses, and more
- **User-friendly Interface**: Modern, responsive design that works on all devices

## Tech Stack

- **Backend**: Python with Flask framework
- **Frontend**: HTML5, CSS3, Bootstrap 5, JavaScript
- **External Libraries**:
  - Chart.js: For data visualization
  - Font Awesome: For icons
  - python-whois: For domain registration data
  - Requests: For HTTP operations

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/phishing-shield.git
   cd phishing-shield
   ```

2. Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

## Usage

1. Enter a URL in the search box
2. Click "Analyze URL"
3. Review the detailed analysis results:
   - Overall risk score
   - Risk breakdown by category
   - Technical details
   - Security recommendations

## Project Structure

```
phishing_shield/
│
├── app.py                     # Main Flask application
├── config.py                  # Configuration settings
├── requirements.txt           # Python dependencies
│
├── static/                    # Static files
│   ├── css/
│   │   └── styles.css         # Custom styling
│   │
│   ├── js/
│   │   ├── app.js             # Main application logic
│   │   ├── ui.js              # UI management code
│   │   └── scoring.js         # Front-end scoring logic
│   │
│   └── data/
│       ├── tld-risk.json      # TLD risk data
│       └── patterns.json      # Phishing patterns data
│
├── templates/                 # HTML templates
│   ├── index.html             # Main page
│   ├── about.html             # About page
│   └── history.html           # History page
│
└── utils/                     # Python utility modules
    ├── __init__.py
    ├── url_analyzers.py       # URL analysis functions
    ├── domain_check.py        # Domain reputation checking
    ├── scoring.py             # Scoring algorithms
    ├── phishing_patterns.py   # Phishing patterns database
    └── safe_domains.py        # Known safe domains
```

## How It Works

1. **URL Structure Analysis**: Examines URL characteristics like length, special characters, and format
2. **Domain Age Check**: Newer domains are more likely to be used for phishing
3. **TLD Risk Assessment**: Some top-level domains are more commonly associated with malicious sites
4. **SSL Certificate Validation**: Verifies proper implementation of HTTPS security
5. **Pattern Detection**: Identifies common patterns used in phishing URLs

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Chart.js](https://www.chartjs.org/) for data visualization
- [Bootstrap](https://getbootstrap.com/) for UI components
- [Font Awesome](https://fontawesome.com/) for icons
- [Flask](https://flask.palletsprojects.com/) for web framework

## Disclaimer

This tool is for educational purposes only. Always exercise caution when visiting unfamiliar websites and never share sensitive information unless you're absolutely certain the site is legitimate.
