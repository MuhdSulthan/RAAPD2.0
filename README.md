# RAAPD2.0

RAAPD: Real-time Anomaly Alert on Port Detector
Unsupported image

🛡️ Overview
RAAPD is an advanced network security monitoring platform that provides comprehensive threat detection through continuous analysis of network traffic patterns. The system leverages machine learning algorithms to identify anomalies and potential security threats in real-time, protecting your organization's valuable data and network infrastructure.

🔑 Key Features
Real-time Network Monitoring: Continuous analysis of traffic across multiple ports with protocol identification and categorization
Machine Learning-Powered Anomaly Detection: Sophisticated algorithms identify unusual traffic patterns that may indicate security threats
PII/SPII Protection: Detection of sensitive personal information movement across the network
Custom Alert Rules: Create organization-specific monitoring criteria based on unique security requirements
Multi-channel Notifications: Receive alerts through email, ntfy.sh, and SMS-style notifications
SIEM Integration: Connect with enterprise security infrastructure through standardized formats (JSON, CEF/LEEF, Syslog)
Interactive Dashboard: Visualize security metrics and events through an intuitive, responsive interface
Comprehensive User Management: Role-based access control with secure authentication
📋 System Requirements
Hardware Requirements
CPU: 4-core minimum (8-core recommended)
Memory: 8GB minimum (16GB recommended)
Storage: 100GB SSD minimum (250GB+ recommended)
Network: Gigabit Ethernet
Software Requirements
Operating System: Linux-based distribution
Python: 3.11 or newer
PostgreSQL: 16.0 or newer
Web Browser: Chrome 90+, Firefox 88+, Safari 14+, or Edge 90+
🚀 Installation
Prerequisites
Ensure PostgreSQL 16+ is installed and running
Python 3.11+ with pip installed
Required environmental variables configured (see Configuration section)
Setup Steps
Clone the repository:

git clone https://github.com/yourusername/raapd.git
cd raapd
Create and activate a virtual environment:

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install dependencies:

pip install -r requirements.txt
Set up the database:

python migrate_db.py
Run additional migration scripts:

python migrate_custom_alert_rules.py
python migrate_ntfy.py
python migrate_pattern_definitions.py
python migrate_siem_integration.py
Start the application:

gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
Access the web interface at http://localhost:5000

⚙️ Configuration
RAAPD uses environment variables for configuration. Create a .env file in the project root with the following variables:

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost/raapd_db
# Email Notification Settings
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=notifications@yourdomain.com
MAIL_PASSWORD=your_mail_password
MAIL_DEFAULT_SENDER=notifications@yourdomain.com
# Twilio SMS Configuration (Optional)
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token
TWILIO_PHONE_NUMBER=your_twilio_phone
# Security Settings
SESSION_SECRET=your_secret_key_here
🔧 Customization
Custom Alert Rules
RAAPD supports custom alert rules to meet your organization's specific security requirements. Rules can be defined through the web interface under Configuration → Custom Rules.

Example rule format:

{
  "name": "Excessive HTTPS Traffic",
  "condition": {
    "port": 443,
    "threshold": 1000,
    "timeframe": 60
  },
  "severity": "MEDIUM",
  "action": "ALERT"
}
Notification Preferences
Users can customize their notification preferences through the user profile page:

Email notifications for all or specific alert types
ntfy.sh integration for instant mobile notifications
SMS-style alerts for critical security events
🔍 Advanced Usage
SIEM Integration
RAAPD integrates with major SIEM platforms through standardized formats:

JSON: Rich hierarchical data with universal support
CEF/LEEF: Standardized security event formats for ArcSight and IBM
Syslog: Lightweight format with broad compatibility
Configure SIEM integration through the web interface under Configuration → SIEM Integration.

Simulation Mode
For testing and demonstration purposes, RAAPD includes a simulation mode that generates realistic network traffic patterns with occasional anomalies and potential data leaks. This mode is automatically enabled when the system doesn't have permissions for real packet capture.

To force simulation mode:

export RAAPD_SIMULATION_MODE=1
📊 Architecture
RAAPD implements a multi-layered architecture:

Data Collection Layer: Captures and preprocesses network traffic data
Analysis Engine Layer: Identifies anomalies and potential security threats
Alert Management Layer: Handles detection, classification, and storage of security incidents
Notification System Layer: Facilitates communication of security events
SIEM Integration Layer: Provides enterprise-level security information management
User Interface Layer: Offers comprehensive system interaction
🔎 Troubleshooting
Common Issues
Issue: System shows "Cannot capture real packets: Operation not permitted"
Solution: Run the application with sufficient permissions or use simulation mode for testing.

Issue: No alerts being generated
Solution: Check that monitoring is enabled and ports are configured correctly in the settings.

Issue: Notification emails not being received
Solution: Verify SMTP settings in the environment configuration and check spam folders.

🤝 Contributing
We welcome contributions to RAAPD! Please follow these steps:

Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

📧 Contact
Project Maintainer - your.email@example.com

Project Repository: https://github.com/yourusername/raapd

RAAPD: Enhancing network security through intelligent monitoring and analysis.
