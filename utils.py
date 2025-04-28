import re
import logging
import json
import os
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

# ntfy.sh configuration - Multiple servers for redundancy and distribution
NTFY_SERVERS = [
    "https://ntfy.sh",
    "https://ntfy.envs.net",
    "https://ntfy.adminforge.de",
    "https://ntfy.debugged.it",
    "https://ntfy.mzte.de",
    "https://ntfy.hostux.net"
]

# Default PII/SPII patterns - these will be used as fallbacks if database is unavailable
DEFAULT_PII_PATTERNS = {
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'phone': r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    'address': r'\b\d+\s+[A-Za-z\s]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
}

DEFAULT_SPII_PATTERNS = {
    'passport': r'\b[A-Za-z]\d{8}\b',
    'dob': r'\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b',
    'medical_record': r'\b(?:MRN|Medical Record Number):\s*\w+\b',
    'driver_license': r'\b[A-Za-z]\d{7}\b'
}

def get_user_patterns(user_id=None, pattern_type='PII'):
    """
    Get custom patterns from the database for a specific user and type.
    
    Args:
        user_id (int): User ID to fetch patterns for (None for default patterns only)
        pattern_type (str): 'PII' or 'SPII'
        
    Returns:
        dict: Dictionary with pattern names as keys and regex patterns as values
    """
    try:
        # This import is intentionally here to avoid circular imports
        from models import PatternDefinition, db
        
        query = PatternDefinition.query.filter_by(
            pattern_type=pattern_type, 
            is_active=True
        )
        
        # If user_id is provided, get both default patterns and user's custom patterns
        if user_id:
            query = query.filter((PatternDefinition.is_default == True) | 
                                (PatternDefinition.user_id == user_id))
        else:
            # Otherwise just get default patterns
            query = query.filter_by(is_default=True)
            
        patterns = {}
        for pattern in query.all():
            patterns[pattern.pattern_name.lower().replace(' ', '_')] = pattern.pattern_regex
            
        return patterns
    except Exception as e:
        logger.error(f"Error fetching patterns from database: {str(e)}")
        # Fallback to defaults if database access fails
        if pattern_type == 'PII':
            return DEFAULT_PII_PATTERNS
        else:
            return DEFAULT_SPII_PATTERNS

def detect_pii(text, user_id=None):
    """
    Detect PII in the given text.
    
    Args:
        text (str): Text to scan for PII
        user_id (int): Optional user ID to use for custom patterns
        
    Returns:
        dict: Dictionary with PII types as keys and lists of matches as values
    """
    results = {}
    
    # Get patterns for this user (falls back to defaults if needed)
    patterns = get_user_patterns(user_id, 'PII')
    
    for pattern_name, pattern in patterns.items():
        try:
            matches = re.findall(pattern, text)
            if matches:
                results[pattern_name] = matches
        except Exception as e:
            logger.error(f"Error with pattern '{pattern_name}': {str(e)}")
    
    return results

def detect_spii(text, user_id=None):
    """
    Detect SPII in the given text.
    
    Args:
        text (str): Text to scan for SPII
        user_id (int): Optional user ID to use for custom patterns
        
    Returns:
        dict: Dictionary with SPII types as keys and lists of matches as values
    """
    results = {}
    
    # Get patterns for this user (falls back to defaults if needed)
    patterns = get_user_patterns(user_id, 'SPII')
    
    for pattern_name, pattern in patterns.items():
        try:
            matches = re.findall(pattern, text)
            if matches:
                results[pattern_name] = matches
        except Exception as e:
            logger.error(f"Error with pattern '{pattern_name}': {str(e)}")
    
    return results

def format_bytes(bytes):
    """
    Format bytes to human-readable format.
    
    Args:
        bytes (int): Number of bytes
        
    Returns:
        str: Formatted string (e.g., "1.23 MB")
    """
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    value = float(bytes)
    
    while value > 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    
    return f"{value:.2f} {units[unit_index]}"

def get_severity_class(severity):
    """
    Get Bootstrap class for severity level.
    
    Args:
        severity (str): Severity level (e.g., 'HIGH', 'MEDIUM', 'LOW')
        
    Returns:
        str: Bootstrap class name
    """
    severity_map = {
        'CRITICAL': 'danger',
        'HIGH': 'danger',
        'MEDIUM': 'warning',
        'LOW': 'info'
    }
    
    return severity_map.get(severity, 'secondary')

def get_alert_type_icon(alert_type):
    """
    Get Font Awesome icon for alert type.
    
    Args:
        alert_type (str): Alert type
        
    Returns:
        str: Font Awesome icon class
    """
    icon_map = {
        'PII_LEAK': 'fa-user-secret',
        'SPII_LEAK': 'fa-exclamation-triangle',
        'TRAFFIC_ANOMALY': 'fa-chart-line'
    }
    
    return icon_map.get(alert_type, 'fa-bell')

def port_service_name(port):
    """
    Get service name for common ports.
    
    Args:
        port (int): Port number
        
    Returns:
        str: Service name or port number as string
    """
    common_ports = {
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        465: 'SMTPS',
        587: 'SMTP (Submission)',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP Alternate',
        8443: 'HTTPS Alternate'
    }
    
    return common_ports.get(port, str(port))

def send_ntfy_notification(topic, title, message, priority="high", tags=None, click=None, preferred_servers=None):
    """
    Send a notification using multiple ntfy.sh servers for redundancy and distribution.
    
    Args:
        topic (str): Topic to publish to (serves as a channel identifier)
        title (str): Notification title
        message (str): Message content
        priority (str): Priority level - "max", "high", "default", "low", "min" (default: "high")
        tags (list): List of emoji tag strings to display (default: None)
        click (str): URL to open when notification is clicked (default: None)
        preferred_servers (list): Optional list of preferred ntfy servers to use (default: None)
        
    Returns:
        bool: True if message sent successfully to at least one server, False otherwise
    """
    successful_servers = 0
    failed_servers = 0
    
    # Use preferred servers if provided, otherwise use defaults
    servers_to_use = []
    if preferred_servers and isinstance(preferred_servers, list) and len(preferred_servers) > 0:
        # Use the user's preferred servers
        servers_to_use = preferred_servers
        logger.info(f"Using {len(servers_to_use)} preferred ntfy servers")
    else:
        # Use all default servers
        servers_to_use = NTFY_SERVERS
        logger.info(f"Using {len(servers_to_use)} default ntfy servers")
    
    # Prepare headers
    headers = {
        "Title": title,
        "Priority": priority
    }
    
    # Add tags if provided
    if tags:
        headers["Tags"] = ",".join(tags)
        
    # Add click URL if provided
    if click:
        headers["Click"] = click
    
    # Encode message once for all requests
    encoded_message = message.encode("utf-8")
    
    # Try sending to all servers in parallel using threads
    import concurrent.futures
    
    def send_to_server(server):
        try:
            url = f"{server}/{topic}"
            response = requests.post(url, data=encoded_message, headers=headers)
            
            if response.status_code == 200:
                logger.info(f"Notification sent successfully to {server}/{topic}")
                return True
            else:
                logger.warning(f"Failed to send notification to {server}/{topic}. Status: {response.status_code}")
                return False
        except Exception as e:
            logger.warning(f"Error sending to {server}/{topic}: {str(e)}")
            return False
    
    # Use ThreadPoolExecutor to send notifications in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(servers_to_use)) as executor:
        # Submit tasks and collect futures
        future_to_server = {executor.submit(send_to_server, server): server for server in servers_to_use}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_server):
            server = future_to_server[future]
            try:
                if future.result():
                    successful_servers += 1
                else:
                    failed_servers += 1
            except Exception as exc:
                logger.error(f"Server {server} generated an exception: {exc}")
                failed_servers += 1
    
    # Log results
    if successful_servers > 0:
        logger.info(f"Notification sent successfully to {successful_servers} out of {len(servers_to_use)} servers")
        return True
    else:
        logger.error("Failed to send notification to any server")
        return False

def send_sms(to_phone_number, message, preferred_servers=None):
    """
    Send SMS-style alerts via ntfy.sh (not actual SMS).
    Twilio integration has been completely removed, all SMS functionality
    now goes through ntfy.sh to avoid extra costs and complexity.
    
    Args:
        to_phone_number (str): Recipient phone number (used to create a consistent ntfy topic)
        message (str): Message content
        preferred_servers (list): Optional list of preferred ntfy servers to use (default: None)
        
    Returns:
        bool: True if message sent successfully, False otherwise
    """
    try:
        # Create a topic based on phone hash for consistency
        topic = f"raapd-{hash(to_phone_number) % 10000000:07d}"
        
        # Send via ntfy.sh
        logger.info(f"Sending SMS-style alert via ntfy.sh to topic {topic}")
        return send_ntfy_notification(
            topic=topic,
            title="RAAPD Security Alert",
            message=message,
            tags=["warning", "shield"],
            priority="high",
            preferred_servers=preferred_servers
        )
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
        return False
