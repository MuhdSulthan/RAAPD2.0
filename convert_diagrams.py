#!/usr/bin/env python3
import os
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DiagramConverter")

# Directory paths
SVG_DIR = "./static/images/diagrams"
PNG_DIR = "./static/images/diagrams/png"

# Create PNG directory if it doesn't exist
os.makedirs(PNG_DIR, exist_ok=True)

# UML diagram filenames
uml_diagrams = [
    "class_diagram.svg",
    "flow_chart.svg", 
    "sequence_diagram.svg",
    "use_case_diagram.svg",
    "activity_diagram.svg"
]

# Fixed SVG for activity diagram with better text alignment
activity_diagram_fixed = """<?xml version="1.0" encoding="UTF-8"?>
<svg width="595" height="842" xmlns="http://www.w3.org/2000/svg">
  <!-- A4 size: 595x842 pixels -->
  <!-- Light Background -->
  <rect width="595" height="842" fill="#ffffff" />
  
  <!-- Title -->
  <text x="297.5" y="40" font-family="Arial, sans-serif" font-size="22" fill="#333333" text-anchor="middle" font-weight="bold">RAAPD System - Activity Diagram</text>
  
  <!-- Start Node -->
  <circle cx="297.5" cy="80" r="15" fill="#000000" />
  
  <!-- User Authentication Activity -->
  <rect x="227.5" y="110" width="140" height="40" rx="10" ry="10" fill="#e3f2fd" stroke="#1976d2" stroke-width="1.5" />
  <text x="297.5" y="135" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">User Authentication</text>
  
  <!-- Authentication Decision -->
  <polygon points="297.5,170 327.5,200 297.5,230 267.5,200" fill="#fff8e1" stroke="#ffab00" stroke-width="1.5" />
  <text x="297.5" y="205" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">Valid?</text>
  
  <!-- No Path - Back to Authentication -->
  <text x="245" y="200" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">No</text>
  <path d="M 267.5 200 C 240 200, 240 130, 267.5 130" fill="none" stroke="#333333" stroke-width="1.5" />
  <polygon points="267.5,130 262.5,140 272.5,140" fill="#333333" />
  
  <!-- Yes Path -->
  <text x="335" y="200" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">Yes</text>
  
  <!-- Dashboard Activity -->
  <rect x="227.5" y="250" width="140" height="40" rx="10" ry="10" fill="#e3f2fd" stroke="#1976d2" stroke-width="1.5" />
  <text x="297.5" y="275" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">Dashboard</text>
  
  <!-- Fork Node -->
  <rect x="262.5" y="310" width="70" height="5" fill="#000000" />
  
  <!-- Left Branch - Configure Network Monitoring -->
  <rect x="125" y="335" width="140" height="40" rx="10" ry="10" fill="#f3e5f5" stroke="#9c27b0" stroke-width="1.5" />
  <text x="195" y="355" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Configure Network</text>
  <text x="195" y="370" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Monitoring</text>
  
  <!-- Right Branch - Configure Keywords -->
  <rect x="330" y="335" width="140" height="40" rx="10" ry="10" fill="#f3e5f5" stroke="#9c27b0" stroke-width="1.5" />
  <text x="400" y="355" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Configure Keyword</text>
  <text x="400" y="370" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Monitoring</text>
  
  <!-- Start Monitoring Decision -->
  <polygon points="195,395 225,425 195,455 165,425" fill="#fff8e1" stroke="#ffab00" stroke-width="1.5" />
  <text x="195" y="430" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">Start?</text>
  
  <!-- No Path - Back to Configure -->
  <text x="165" y="415" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">No</text>
  <path d="M 165 425 C 140 425, 140 355, 165 355" fill="none" stroke="#333333" stroke-width="1.5" />
  <polygon points="165,355 160,365 170,365" fill="#333333" />
  
  <!-- Yes Path -->
  <text x="230" y="425" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">Yes</text>
  
  <!-- Join Node (before Packet Capture) -->
  <rect x="262.5" y="475" width="70" height="5" fill="#000000" />
  
  <!-- Packet Capture Activity -->
  <rect x="227.5" y="500" width="140" height="40" rx="10" ry="10" fill="#e8f5e9" stroke="#388e3c" stroke-width="1.5" />
  <text x="297.5" y="525" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">Packet Capture</text>
  
  <!-- Anomaly Detection Activity -->
  <rect x="227.5" y="560" width="140" height="40" rx="10" ry="10" fill="#ffebee" stroke="#c62828" stroke-width="1.5" />
  <text x="297.5" y="585" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">Anomaly Detection</text>
  
  <!-- Anomaly Decision -->
  <polygon points="297.5,620 327.5,650 297.5,680 267.5,650" fill="#fff8e1" stroke="#ffab00" stroke-width="1.5" />
  <text x="297.5" y="655" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">Anomaly?</text>
  
  <!-- No Path - Continue Monitoring -->
  <text x="245" y="650" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">No</text>
  <path d="M 267.5 650 C 200 650, 200 520, 227.5 520" fill="none" stroke="#333333" stroke-width="1.5" />
  <polygon points="227.5,520 222.5,530 232.5,530" fill="#333333" />
  
  <!-- Yes Path -->
  <text x="335" y="650" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">Yes</text>
  
  <!-- Alert Generation Activity -->
  <rect x="430" y="630" width="140" height="40" rx="10" ry="10" fill="#ffebee" stroke="#c62828" stroke-width="1.5" />
  <text x="500" y="655" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle">Generate Alert</text>
  
  <!-- Fork Node (for notifications) -->
  <rect x="465" y="690" width="70" height="5" fill="#000000" />
  
  <!-- Email Notification Activity -->
  <rect x="380" y="710" width="100" height="40" rx="10" ry="10" fill="#fce4ec" stroke="#c2185b" stroke-width="1.5" />
  <text x="430" y="733" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Email</text>
  <text x="430" y="748" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Notification</text>
  
  <!-- ntfy.sh Notification Activity -->
  <rect x="520" y="710" width="100" height="40" rx="10" ry="10" fill="#fce4ec" stroke="#c2185b" stroke-width="1.5" />
  <text x="570" y="733" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">ntfy.sh</text>
  <text x="570" y="748" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Notification</text>
  
  <!-- SIEM Export Activity -->
  <rect x="105" y="710" width="100" height="40" rx="10" ry="10" fill="#e8eaf6" stroke="#3949ab" stroke-width="1.5" />
  <text x="155" y="733" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">SIEM</text>
  <text x="155" y="748" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Export</text>
  
  <!-- Alert Review Activity -->
  <rect x="240" y="710" width="100" height="40" rx="10" ry="10" fill="#fff8e1" stroke="#f57f17" stroke-width="1.5" />
  <text x="290" y="733" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">Mark Alert</text>
  <text x="290" y="748" font-family="Arial, sans-serif" font-size="13" fill="#333333" text-anchor="middle">as Reviewed</text>
  
  <!-- End Node for Review -->
  <circle cx="290" cy="770" r="12" fill="#ffffff" stroke="#000000" stroke-width="2" />
  <circle cx="290" cy="770" r="6" fill="#000000" />
  
  <!-- End Node for Notifications -->
  <circle cx="500" cy="770" r="12" fill="#ffffff" stroke="#000000" stroke-width="2" />
  <circle cx="500" cy="770" r="6" fill="#000000" />
  
  <!-- End Node for SIEM -->
  <circle cx="155" cy="770" r="12" fill="#ffffff" stroke="#000000" stroke-width="2" />
  <circle cx="155" cy="770" r="6" fill="#000000" />
  
  <!-- Connect Start to Authentication -->
  <line x1="297.5" y1="95" x2="297.5" y2="110" stroke="#333333" stroke-width="1.5" />
  <polygon points="297.5,110 292.5,100 302.5,100" fill="#333333" />
  
  <!-- Connect Authentication to Decision -->
  <line x1="297.5" y1="150" x2="297.5" y2="170" stroke="#333333" stroke-width="1.5" />
  <polygon points="297.5,170 292.5,160 302.5,160" fill="#333333" />
  
  <!-- Connect Decision to Dashboard -->
  <line x1="297.5" y1="230" x2="297.5" y2="250" stroke="#333333" stroke-width="1.5" />
  <polygon points="297.5,250 292.5,240 302.5,240" fill="#333333" />
  
  <!-- Connect Dashboard to Fork -->
  <line x1="297.5" y1="290" x2="297.5" y2="310" stroke="#333333" stroke-width="1.5" />
  <polygon points="297.5,310 292.5,300 302.5,300" fill="#333333" />
  
  <!-- Connect Fork to Left Activity -->
  <line x1="262.5" y1="312.5" x2="195" y2="312.5" stroke="#333333" stroke-width="1.5" />
  <line x1="195" y1="312.5" x2="195" y2="335" stroke="#333333" stroke-width="1.5" />
  <polygon points="195,335 190,325 200,325" fill="#333333" />
  
  <!-- Connect Fork to Right Activity -->
  <line x1="332.5" y1="312.5" x2="400" y2="312.5" stroke="#333333" stroke-width="1.5" />
  <line x1="400" y1="312.5" x2="400" y2="335" stroke="#333333" stroke-width="1.5" />
  <polygon points="400,335 395,325 405,325" fill="#333333" />
  
  <!-- Connect Left Activity to Decision -->
  <line x1="195" y1="375" x2="195" y2="395" stroke="#333333" stroke-width="1.5" />
  <polygon points="195,395 190,385 200,385" fill="#333333" />
  
  <!-- Connect Decision to Join -->
  <line x1="195" y1="455" x2="195" y2="475" stroke="#333333" stroke-width="1.5" />
  <line x1="195" y1="477.5" x2="262.5" y2="477.5" stroke="#333333" stroke-width="1.5" />
  <polygon points="262.5,477.5 252.5,472.5 252.5,482.5" fill="#333333" />
  
  <!-- Connect Right Activity to Join -->
  <line x1="400" y1="375" x2="400" y2="477.5" stroke="#333333" stroke-width="1.5" />
  <line x1="400" y1="477.5" x2="332.5" y2="477.5" stroke="#333333" stroke-width="1.5" />
  <polygon points="332.5,477.5 342.5,472.5 342.5,482.5" fill="#333333" />
  
  <!-- Connect Join to Packet Capture -->
  <line x1="297.5" y1="480" x2="297.5" y2="500" stroke="#333333" stroke-width="1.5" />
  <polygon points="297.5,500 292.5,490 302.5,490" fill="#333333" />
  
  <!-- Connect Packet Capture to Anomaly Detection -->
  <line x1="297.5" y1="540" x2="297.5" y2="560" stroke="#333333" stroke-width="1.5" />
  <polygon points="297.5,560 292.5,550 302.5,550" fill="#333333" />
  
  <!-- Connect Anomaly Detection to Decision -->
  <line x1="297.5" y1="600" x2="297.5" y2="620" stroke="#333333" stroke-width="1.5" />
  <polygon points="297.5,620 292.5,610 302.5,610" fill="#333333" />
  
  <!-- Connect Decision to Alert Generation -->
  <line x1="327.5" y1="650" x2="430" y2="650" stroke="#333333" stroke-width="1.5" />
  <polygon points="430,650 420,645 420,655" fill="#333333" />
  
  <!-- Connect Alert Generation to Fork -->
  <line x1="500" y1="670" x2="500" y2="690" stroke="#333333" stroke-width="1.5" />
  <polygon points="500,690 495,680 505,680" fill="#333333" />
  
  <!-- Connect Fork to Email Notification -->
  <line x1="465" y1="692.5" x2="430" y2="692.5" stroke="#333333" stroke-width="1.5" />
  <line x1="430" y1="692.5" x2="430" y2="710" stroke="#333333" stroke-width="1.5" />
  <polygon points="430,710 425,700 435,700" fill="#333333" />
  
  <!-- Connect Fork to ntfy.sh Notification -->
  <line x1="535" y1="692.5" x2="570" y2="692.5" stroke="#333333" stroke-width="1.5" />
  <line x1="570" y1="692.5" x2="570" y2="710" stroke="#333333" stroke-width="1.5" />
  <polygon points="570,710 565,700 575,700" fill="#333333" />
  
  <!-- Connect Alert Generation to SIEM Export -->
  <path d="M 430 650 C 120 650, 120 680, 155 710" fill="none" stroke="#333333" stroke-width="1.5" />
  <polygon points="155,710 150,700 160,700" fill="#333333" />
  
  <!-- Connect Alert Generation to Alert Review -->
  <path d="M 430 650 C 290 650, 290 680, 290 710" fill="none" stroke="#333333" stroke-width="1.5" />
  <polygon points="290,710 285,700 295,700" fill="#333333" />
  
  <!-- Connect Activities to End Nodes -->
  <line x1="430" y1="750" x2="430" y2="770" stroke="#333333" stroke-width="1.5" />
  <line x1="430" y1="770" x2="488" y2="770" stroke="#333333" stroke-width="1.5" />
  
  <line x1="570" y1="750" x2="570" y2="770" stroke="#333333" stroke-width="1.5" />
  <line x1="570" y1="770" x2="512" y2="770" stroke="#333333" stroke-width="1.5" />
  
  <line x1="290" y1="750" x2="290" y2="770" stroke="#333333" stroke-width="1.5" />
  
  <line x1="155" y1="750" x2="155" y2="770" stroke="#333333" stroke-width="1.5" />
  
  <!-- Legend -->
  <rect x="160" y="790" width="275" height="40" fill="#f5f5f5" stroke="#9e9e9e" stroke-width="1" />
  <text x="297.5" y="805" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle" font-weight="bold">Legend</text>
  
  <circle cx="175" cy="825" r="6" fill="#000000" />
  <text x="195" y="830" font-family="Arial, sans-serif" font-size="12" fill="#333333">Start/Initial Node</text>
  
  <circle cx="240" cy="825" r="6" fill="#ffffff" stroke="#000000" stroke-width="1.5" />
  <circle cx="240" cy="825" r="3" fill="#000000" />
  <text x="270" y="830" font-family="Arial, sans-serif" font-size="12" fill="#333333">End Node</text>
  
  <rect x="300" y="820" width="35" height="10" rx="2" ry="2" fill="#e3f2fd" stroke="#1976d2" stroke-width="1" />
  <text x="340" y="830" font-family="Arial, sans-serif" font-size="12" fill="#333333">Activity</text>
  
  <polygon points="380,820 395,830 380,840 365,830" fill="#fff8e1" stroke="#ffab00" stroke-width="1" />
  <text x="410" y="830" font-family="Arial, sans-serif" font-size="12" fill="#333333">Decision</text>
</svg>"""

# Fixed SVG for class diagram with better alignment
class_diagram_fixed = """<?xml version="1.0" encoding="UTF-8"?>
<svg width="595" height="842" xmlns="http://www.w3.org/2000/svg">
  <!-- A4 size: 595x842 pixels -->
  <!-- Light Background -->
  <rect width="595" height="842" fill="#ffffff" />
  
  <!-- Title -->
  <text x="297.5" y="40" font-family="Arial, sans-serif" font-size="22" fill="#333333" text-anchor="middle" font-weight="bold">RAAPD System - Class Diagram</text>
  
  <!-- NetworkAnalyzer Class -->
  <rect x="60" y="100" width="200" height="180" fill="#e3f2fd" stroke="#1976d2" stroke-width="1.5" />
  <line x1="60" y1="130" x2="260" y2="130" stroke="#1976d2" stroke-width="1.5" />
  <line x1="60" y1="190" x2="260" y2="190" stroke="#1976d2" stroke-width="1.5" />
  <text x="160" y="120" font-family="Arial, sans-serif" font-size="16" fill="#1976d2" text-anchor="middle" font-weight="bold">NetworkAnalyzer</text>
  
  <!-- NetworkAnalyzer Attributes -->
  <text x="70" y="150" font-family="Arial, sans-serif" font-size="14" fill="#333333">- packet_counter: dict</text>
  <text x="70" y="170" font-family="Arial, sans-serif" font-size="14" fill="#333333">- pii_spii_detections: list</text>
  
  <!-- NetworkAnalyzer Methods -->
  <text x="70" y="210" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ capture_packets(duration): dict</text>
  <text x="70" y="230" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ reset_counters(): void</text>
  <text x="70" y="250" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ set_keywords(keywords): void</text>
  <text x="70" y="270" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ apply_custom_rules(config): void</text>

  <!-- AnomalyDetector Class -->
  <rect x="335" y="100" width="200" height="140" fill="#e3f2fd" stroke="#1976d2" stroke-width="1.5" />
  <line x1="335" y1="130" x2="535" y2="130" stroke="#1976d2" stroke-width="1.5" />
  <line x1="335" y1="170" x2="535" y2="170" stroke="#1976d2" stroke-width="1.5" />
  <text x="435" y="120" font-family="Arial, sans-serif" font-size="16" fill="#1976d2" text-anchor="middle" font-weight="bold">AnomalyDetector</text>
  
  <!-- AnomalyDetector Attributes -->
  <text x="345" y="150" font-family="Arial, sans-serif" font-size="14" fill="#333333">- threshold: float</text>
  
  <!-- AnomalyDetector Methods -->
  <text x="345" y="190" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ train_model(data): void</text>
  <text x="345" y="210" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ detect_anomalies(data): list</text>
  <text x="345" y="230" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ update_threshold(value): void</text>

  <!-- Alert Class -->
  <rect x="60" y="340" width="200" height="160" fill="#fff8e1" stroke="#ff8f00" stroke-width="1.5" />
  <line x1="60" y1="370" x2="260" y2="370" stroke="#ff8f00" stroke-width="1.5" />
  <line x1="60" y1="430" x2="260" y2="430" stroke="#ff8f00" stroke-width="1.5" />
  <text x="160" y="360" font-family="Arial, sans-serif" font-size="16" fill="#ff8f00" text-anchor="middle" font-weight="bold">Alert</text>
  
  <!-- Alert Attributes -->
  <text x="70" y="390" font-family="Arial, sans-serif" font-size="14" fill="#333333">- id: int</text>
  <text x="70" y="410" font-family="Arial, sans-serif" font-size="14" fill="#333333">- timestamp: datetime</text>
  
  <!-- Alert Methods -->
  <text x="70" y="450" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ mark_as_reviewed(): void</text>
  <text x="70" y="470" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ send_notification(): void</text>
  <text x="70" y="490" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ export_to_siem(): void</text>

  <!-- User Class -->
  <rect x="335" y="340" width="200" height="160" fill="#fff8e1" stroke="#ff8f00" stroke-width="1.5" />
  <line x1="335" y1="370" x2="535" y2="370" stroke="#ff8f00" stroke-width="1.5" />
  <line x1="335" y1="430" x2="535" y2="430" stroke="#ff8f00" stroke-width="1.5" />
  <text x="435" y="360" font-family="Arial, sans-serif" font-size="16" fill="#ff8f00" text-anchor="middle" font-weight="bold">User</text>
  
  <!-- User Attributes -->
  <text x="345" y="390" font-family="Arial, sans-serif" font-size="14" fill="#333333">- id: int</text>
  <text x="345" y="410" font-family="Arial, sans-serif" font-size="14" fill="#333333">- email: string</text>
  
  <!-- User Methods -->
  <text x="345" y="450" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ login(): bool</text>
  <text x="345" y="470" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ update_preferences(): void</text>
  <text x="345" y="490" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ add_keyword(): void</text>

  <!-- SIEMIntegration Class -->
  <rect x="60" y="560" width="200" height="140" fill="#e8eaf6" stroke="#3949ab" stroke-width="1.5" />
  <line x1="60" y1="590" x2="260" y2="590" stroke="#3949ab" stroke-width="1.5" />
  <line x1="60" y1="630" x2="260" y2="630" stroke="#3949ab" stroke-width="1.5" />
  <text x="160" y="580" font-family="Arial, sans-serif" font-size="16" fill="#3949ab" text-anchor="middle" font-weight="bold">SIEMIntegration</text>
  
  <!-- SIEMIntegration Attributes -->
  <text x="70" y="610" font-family="Arial, sans-serif" font-size="14" fill="#333333">- endpoint_url: string</text>
  
  <!-- SIEMIntegration Methods -->
  <text x="70" y="650" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ configure(endpoint): void</text>
  <text x="70" y="670" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ export_alert(alert): bool</text>
  <text x="70" y="690" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ test_connection(): bool</text>

  <!-- NotificationService Class -->
  <rect x="335" y="560" width="200" height="140" fill="#e8eaf6" stroke="#3949ab" stroke-width="1.5" />
  <line x1="335" y1="590" x2="535" y2="590" stroke="#3949ab" stroke-width="1.5" />
  <line x1="335" y1="630" x2="535" y2="630" stroke="#3949ab" stroke-width="1.5" />
  <text x="435" y="580" font-family="Arial, sans-serif" font-size="16" fill="#3949ab" text-anchor="middle" font-weight="bold">NotificationService</text>
  
  <!-- NotificationService Attributes -->
  <text x="345" y="610" font-family="Arial, sans-serif" font-size="14" fill="#333333">- active: bool</text>
  
  <!-- NotificationService Methods -->
  <text x="345" y="650" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ send_email(alert): bool</text>
  <text x="345" y="670" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ send_ntfy(alert): bool</text>
  <text x="345" y="690" font-family="Arial, sans-serif" font-size="14" fill="#333333">+ toggle_service(): void</text>

  <!-- Relationships -->
  <!-- User to Alert: one-to-many -->
  <line x1="335" y1="420" x2="260" y2="420" stroke="#333333" stroke-width="1.5" stroke-dasharray="5,5" />
  <text x="300" y="410" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">1..n</text>
  <polygon points="260,420 270,415 270,425" fill="#333333" />

  <!-- NetworkAnalyzer to AnomalyDetector: uses -->
  <line x1="260" y1="150" x2="335" y2="150" stroke="#333333" stroke-width="1.5" stroke-dasharray="5,5" />
  <text x="300" y="140" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">uses</text>
  <polygon points="335,150 325,145 325,155" fill="#333333" />

  <!-- NetworkAnalyzer to Alert: creates -->
  <line x1="160" y1="280" x2="160" y2="340" stroke="#333333" stroke-width="1.5" />
  <text x="175" y="310" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">creates</text>
  <polygon points="160,340 155,330 165,330" fill="#333333" />

  <!-- Alert to SIEMIntegration: uses -->
  <line x1="160" y1="500" x2="160" y2="560" stroke="#333333" stroke-width="1.5" stroke-dasharray="5,5" />
  <text x="175" y="530" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">uses</text>
  <polygon points="160,560 155,550 165,550" fill="#333333" />

  <!-- Alert to NotificationService: uses -->
  <line x1="260" y1="480" x2="370" y2="560" stroke="#333333" stroke-width="1.5" stroke-dasharray="5,5" />
  <text x="325" y="510" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">uses</text>
  <polygon points="370,560 360,550 370,545" fill="#333333" />

  <!-- User to NotificationService: configures -->
  <line x1="435" y1="500" x2="435" y2="560" stroke="#333333" stroke-width="1.5" />
  <text x="450" y="530" font-family="Arial, sans-serif" font-size="12" fill="#333333" text-anchor="middle">configures</text>
  <polygon points="435,560 430,550 440,550" fill="#333333" />

  <!-- Legend -->
  <rect x="160" y="740" width="275" height="70" fill="#f5f5f5" stroke="#9e9e9e" stroke-width="1" />
  <text x="297.5" y="760" font-family="Arial, sans-serif" font-size="14" fill="#333333" text-anchor="middle" font-weight="bold">Legend</text>
  
  <rect x="170" y="775" width="60" height="25" fill="#e3f2fd" stroke="#1976d2" stroke-width="1" />
  <text x="250" y="790" font-family="Arial, sans-serif" font-size="12" fill="#333333">Core System Classes</text>
  
  <rect x="170" y="805" width="60" height="25" fill="#fff8e1" stroke="#ff8f00" stroke-width="1" />
  <text x="250" y="820" font-family="Arial, sans-serif" font-size="12" fill="#333333">Data Model Classes</text>
  
  <rect x="170" y="835" width="60" height="25" fill="#e8eaf6" stroke="#3949ab" stroke-width="1" />
  <text x="250" y="850" font-family="Arial, sans-serif" font-size="12" fill="#333333">Service Classes</text>
  
  <line x1="340" y1="775" x2="400" y2="775" stroke="#333333" stroke-width="1.5" />
  <text x="440" y="780" font-family="Arial, sans-serif" font-size="12" fill="#333333">Association</text>
  
  <line x1="340" y1="805" x2="400" y2="805" stroke="#333333" stroke-width="1.5" stroke-dasharray="5,5" />
  <text x="440" y="810" font-family="Arial, sans-serif" font-size="12" fill="#333333">Dependency</text>
</svg>"""

def update_svg_diagrams():
    """Update SVG diagrams with better alignment"""
    try:
        # Update the activity diagram with better alignment
        with open(os.path.join(SVG_DIR, "activity_diagram.svg"), "w") as f:
            f.write(activity_diagram_fixed)
        
        # Update the class diagram with better alignment
        with open(os.path.join(SVG_DIR, "class_diagram.svg"), "w") as f:
            f.write(class_diagram_fixed)
        
        logger.info("Updated SVG diagrams with better alignment")
        return True
    except Exception as e:
        logger.error(f"Error updating SVG diagrams: {e}")
        return False

def create_png_diagrams():
    """Convert SVG diagrams to PNG format using ImageMagick"""
    for svg_file in uml_diagrams:
        svg_path = os.path.join(SVG_DIR, svg_file)
        png_file = os.path.splitext(svg_file)[0] + ".png"
        png_path = os.path.join(PNG_DIR, png_file)
        
        try:
            # Using convert command from ImageMagick to convert SVG to PNG
            command = f"convert -density 300 {svg_path} -quality 100 {png_path}"
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            logger.info(f"Successfully converted {svg_file} to PNG at {png_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to convert {svg_file} to PNG: {e.stderr}")


if __name__ == "__main__":
    # First update the SVG files for better alignment
    if update_svg_diagrams():
        # Then create PNG versions of all UML diagrams
        create_png_diagrams()
    else:
        logger.error("Failed to update SVG diagrams, aborting PNG creation.")