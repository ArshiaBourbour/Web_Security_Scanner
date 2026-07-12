
# 🛡️ 4EYEZ – Web Security Scanner

<p align="center">
  <strong>A modular Python-based Web Security Scanner for educational purposes.</strong>
</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker)
![Docker Compose](https://img.shields.io/badge/Docker_Compose-Ready-2496ED?logo=docker)
![GitHub Actions](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions)
![Pytest](https://img.shields.io/badge/Tests-107_Passing-success?logo=pytest)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-v1.0.0-orange)

</p>

---

## ⚠️ Educational Disclaimer

**This project was created solely for educational purposes.**

It demonstrates defensive web security concepts such as HTTP security headers, HTTPS configuration, sitemap analysis, risk scoring, and report generation.

It is **not intended for malicious activity** or unauthorized scanning. Only scan systems that you own or have explicit permission to assess.

---

# ✨ Features

- Security Header Analysis
- CSP / HSTS / CORS checks
- Clickjacking detection
- HTTP Methods analysis
- Sensitive Paths inspection
- Sitemap analysis
- Executive Summary
- Risk Score Engine
- HTML / PDF / JSON reports
- Docker support
- Docker Compose support
- GitHub Actions CI
- 107 automated unit tests

---

# 📂 Project Structure

```text
Web_Security_Scanner/
├── app.py
├── scanner/
├── reports/
├── tests/
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/
└── requirements*.txt
```

# 🚀 Installation

```bash
git clone https://github.com/ArshiaBourbour/Web_Security_Scanner.git
cd Web_Security_Scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
python app.py
```

# 🐳 Docker

```bash
docker build -t web-security-scanner .
docker run -it web-security-scanner
```

# 🐳 Docker Compose

```bash
docker compose up
```

Stop:

```bash
docker compose down
```

# 🧪 Running Tests

```bash
python -m pytest
```

Current status:

- ✅ 107 tests passing

# ⚙️ Continuous Integration

GitHub Actions automatically:

- Installs dependencies
- Runs pytest
- Validates every push and pull request

# 📊 Reports

Generated reports include:

- HTML
- PDF
- JSON

Example output directory:

```text
reports/
```

# 🎬 Demo

Add your demo GIF:

```text
assets/demo.gif
```

# 🖼️ Screenshots

Place your screenshots inside:

```text
assets/screenshots/
```

Example:

```md
![CLI](assets/screenshots/cli.png)
![HTML Report](assets/screenshots/html-report.png)
![PDF Report](assets/screenshots/pdf-report.png)
```

# 🛣️ Roadmap

- [x] Core Scanner
- [x] Report Generator
- [x] Unit Testing
- [x] Docker
- [x] Docker Compose
- [x] GitHub Actions
- [x] Version 1.0.0

# 🤝 Contributing

Contributions are welcome.

Fork the repository, create a feature branch, commit your changes and open a Pull Request.

# 📄 License

This project is licensed under the MIT License.

# 👨‍💻 Author

**Arshia Bourbour**

GitHub:
https://github.com/ArshiaBourbour

---

⭐ If you found this project useful, consider giving it a star.
