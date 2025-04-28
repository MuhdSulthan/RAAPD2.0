from app import db
from datetime import datetime
import json
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # User preferences for notifications
    notifications_enabled = db.Column(db.Boolean, default=True)  # Master switch for all notifications
    email_alerts = db.Column(db.Boolean, default=True)
    sms_alerts = db.Column(db.Boolean, default=False)
    ntfy_alerts = db.Column(db.Boolean, default=True)  # New: ntfy.sh notification preference
    ntfy_topic = db.Column(db.String(100))  # New: ntfy.sh topic for this user
    ntfy_servers = db.Column(db.Text, default='[]')  # JSON string of preferred ntfy servers
    alert_on_pii = db.Column(db.Boolean, default=True)
    alert_on_spii = db.Column(db.Boolean, default=True)
    alert_on_anomaly = db.Column(db.Boolean, default=True)
    alert_on_keywords = db.Column(db.Boolean, default=True)
    
    # Track notification state
    lockout_notification_sent = db.Column(db.Boolean, default=False)  # Flag to track if lockout notification was sent

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked(self):
        """Check if the user account is locked."""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'phone': self.phone,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'notifications_enabled': self.notifications_enabled,
            'email_alerts': self.email_alerts,
            'sms_alerts': self.sms_alerts,
            'ntfy_alerts': self.ntfy_alerts,
            'ntfy_topic': self.ntfy_topic,
            'alert_preferences': {
                'pii': self.alert_on_pii,
                'spii': self.alert_on_spii,
                'anomaly': self.alert_on_anomaly,
                'keywords': self.alert_on_keywords
            }
        }

class Keyword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    keyword = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    priority = db.Column(db.String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('keywords', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'keyword': self.keyword,
            'description': self.description,
            'priority': self.priority,
            'created_at': self.created_at.isoformat(),
            'active': self.active
        }

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert_type = db.Column(db.String(50), nullable=False)  # e.g., 'PII_LEAK', 'TRAFFIC_ANOMALY', 'KEYWORD_MATCH'
    severity = db.Column(db.String(20), nullable=False)    # e.g., 'HIGH', 'MEDIUM', 'LOW'
    message = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))  # New field for protocol (TCP, UDP, etc.)
    payload_excerpt = db.Column(db.Text)  # Excerpt from the packet payload (sanitized)
    reviewed = db.Column(db.Boolean, default=False)
    
    # Optional association with a user (for keyword alerts)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('alerts', lazy='dynamic'))
    
    # Optional association with a keyword
    keyword_id = db.Column(db.Integer, db.ForeignKey('keyword.id'))
    keyword = db.relationship('Keyword', backref=db.backref('alerts', lazy='dynamic'))
    
    # Notification status
    email_sent = db.Column(db.Boolean, default=False)
    sms_sent = db.Column(db.Boolean, default=False)
    ntfy_sent = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'message': self.message,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'protocol': self.protocol,
            'payload_excerpt': self.payload_excerpt,
            'reviewed': self.reviewed,
            'email_sent': self.email_sent,
            'sms_sent': self.sms_sent,
            'ntfy_sent': self.ntfy_sent,
            'keyword_id': self.keyword_id
        }

class PacketLog(db.Model):
    """Model to store summary information about captured packets"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    length = db.Column(db.Integer)
    flags = db.Column(db.String(50))
    description = db.Column(db.Text)
    
    # Add user relationship
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('packet_logs', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'length': self.length,
            'flags': self.flags,
            'description': self.description
        }

class NetworkStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    port = db.Column(db.Integer, nullable=False)
    packet_count = db.Column(db.Integer, default=0)
    bytes_transferred = db.Column(db.Integer, default=0)
    
    # Add user relationship
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('network_stats', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'port': self.port,
            'packet_count': self.packet_count,
            'bytes_transferred': self.bytes_transferred
        }

class PatternDefinition(db.Model):
    """Model for storing custom PII/SPII pattern definitions"""
    id = db.Column(db.Integer, primary_key=True)
    pattern_name = db.Column(db.String(100), nullable=False)
    pattern_regex = db.Column(db.String(500), nullable=False)
    pattern_type = db.Column(db.String(20), nullable=False)  # 'PII' or 'SPII'
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    is_default = db.Column(db.Boolean, default=False)  # True for system defaults
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add user relationship
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('patterns', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'pattern_name': self.pattern_name,
            'pattern_regex': self.pattern_regex,
            'pattern_type': self.pattern_type,
            'description': self.description,
            'is_active': self.is_active,
            'is_default': self.is_default,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user_id': self.user_id
        }


class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    monitored_ports = db.Column(db.String(255), default="80,443,8080")  # Comma-separated list of ports
    pii_patterns = db.Column(db.Boolean, default=True)  # Enable PII pattern detection
    spii_patterns = db.Column(db.Boolean, default=True)  # Enable SPII pattern detection
    alert_threshold = db.Column(db.Float, default=0.7)  # Threshold for anomaly detection (0.0-1.0)
    monitoring_active = db.Column(db.Boolean, default=True)  # Monitor network traffic
    
    # Custom alert rules and thresholds
    custom_rules = db.Column(db.Text, default='[]')  # JSON string of custom rules
    packet_threshold = db.Column(db.Integer, default=1000)  # Alert if packets exceed this threshold
    bandwidth_threshold = db.Column(db.Integer, default=1000000)  # Alert if bandwidth exceeds this threshold (bytes)
    alert_on_port_scan = db.Column(db.Boolean, default=True)  # Alert on port scanning activity
    port_scan_threshold = db.Column(db.Integer, default=5)  # Number of ports in short time to trigger port scan alert
    
    # SIEM integration configuration
    siem_config = db.Column(db.Text, default='{"enabled": false, "methods": ["syslog"], "format": "cef"}')
    
    # Add user relationship
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('configs', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'monitored_ports': self.monitored_ports,
            'pii_patterns': self.pii_patterns,
            'spii_patterns': self.spii_patterns,
            'alert_threshold': self.alert_threshold,
            'monitoring_active': self.monitoring_active,
            'custom_rules': self.custom_rules,
            'packet_threshold': self.packet_threshold,
            'bandwidth_threshold': self.bandwidth_threshold,
            'alert_on_port_scan': self.alert_on_port_scan,
            'port_scan_threshold': self.port_scan_threshold,
            'siem_config': self.get_siem_config()
        }
    
    def get_custom_rules(self):
        """Parse and return the custom rules as a Python list"""
        import json
        try:
            return json.loads(self.custom_rules)
        except:
            return []
            
    def set_custom_rules(self, rules):
        """Set custom rules from a Python list or dict, converting to JSON string"""
        import json
        try:
            self.custom_rules = json.dumps(rules)
            return True
        except:
            return False
            
    def get_siem_config(self):
        """Parse and return the SIEM configuration as a Python dict"""
        import json
        try:
            return json.loads(self.siem_config)
        except:
            return {"enabled": False, "methods": ["syslog"], "format": "cef"}
    
    def set_siem_config(self, config):
        """Set SIEM configuration from a Python dict, converting to JSON string"""
        import json
        try:
            if isinstance(config, dict):
                self.siem_config = json.dumps(config)
            else:
                self.siem_config = '{"enabled": false, "methods": ["syslog"], "format": "cef"}'
            return True
        except:
            return False
            
            
class SIEMConnection(db.Model):
    """
    Stores configurations for connecting to SIEM systems.
    Each user can have multiple SIEM connection configurations.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    connection_name = db.Column(db.String(100), nullable=False)
    connection_type = db.Column(db.String(50), nullable=False)  # syslog, webhook, elastic, splunk, sentinel
    connection_details = db.Column(db.Text, nullable=False)     # JSON string with connection parameters
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('siem_connections', lazy='dynamic'))
    
    def to_dict(self):
        """Convert to dictionary representation"""
        import json
        
        return {
            'id': self.id,
            'user_id': self.user_id,
            'connection_name': self.connection_name,
            'connection_type': self.connection_type,
            'connection_details': json.loads(self.connection_details) if self.connection_details else {},
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def get_connection_details(self):
        """Parse and return connection details as a Python dict"""
        import json
        try:
            return json.loads(self.connection_details)
        except:
            return {}
    
    def set_connection_details(self, details):
        """Set connection details from a Python dict"""
        import json
        try:
            if isinstance(details, dict):
                self.connection_details = json.dumps(details)
            else:
                self.connection_details = '{}'
            return True
        except:
            return False


class SIEMExport(db.Model):
    """
    Records of alert exports to SIEM systems.
    Tracks which alerts were sent to which SIEM systems and their status.
    """
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alert.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'))
    export_method = db.Column(db.String(50), nullable=False)  # syslog, webhook, elastic, splunk, sentinel
    export_status = db.Column(db.String(20), nullable=False)  # success, error, pending
    export_destination = db.Column(db.String(255))           # Destination address/URL
    export_time = db.Column(db.DateTime, default=datetime.utcnow)
    response_data = db.Column(db.Text)                       # JSON string with response details
    
    # Relationships
    alert = db.relationship('Alert', backref=db.backref('siem_exports', lazy='dynamic'))
    user = db.relationship('User', backref=db.backref('siem_exports', lazy='dynamic'))
    
    def to_dict(self):
        """Convert to dictionary representation"""
        import json
        
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'user_id': self.user_id,
            'export_method': self.export_method,
            'export_status': self.export_status,
            'export_destination': self.export_destination,
            'export_time': self.export_time.isoformat() if self.export_time else None,
            'response_data': json.loads(self.response_data) if self.response_data else {}
        }
    
    def get_response_data(self):
        """Parse and return response data as a Python dict"""
        import json
        try:
            return json.loads(self.response_data)
        except:
            return {}
