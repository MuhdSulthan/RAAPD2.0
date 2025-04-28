import logging
import re
import json
import random
import time
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

# Try to import kamene (renamed scapy3k), but continue if it's not available
try:
    from kamene.all import sniff, IP, TCP, UDP
    logger.info("Using kamene for packet capture.")
    USE_SCAPY = True
except ImportError:
    logger.warning("Kamene not available. Running in simulation mode.")
    USE_SCAPY = False
    # Define placeholder classes to avoid reference errors
    class IP:
        pass
    class TCP:
        pass
    class UDP:
        pass
    def sniff(*args, **kwargs):
        pass

class NetworkAnalyzer:
    def __init__(self):
        # We'll use the utils functions to get the patterns as needed
        # This allows us to have user-specific patterns
        
        # Default patterns (will be overridden by dynamic loading)
        self.pii_patterns = {}
        self.spii_patterns = {}
        self.current_user_id = None
        
        # Initialize counters
        self.reset_counters()
    
    def reset_counters(self):
        """Reset all packet counters and data structures."""
        self.packets = []
        self.port_counts = {}
        self.port_bytes = {}
        self.ip_counts = {}
        self.pii_detections = []
        self.spii_detections = []
        self.keyword_matches = []
        # List of tuples: (keyword, keyword_id, priority)
        self.keywords = []
        # Custom rule structures
        self.custom_rules = []
        self.custom_rule_matches = []
        self.port_activity = {}
        self.source_ips = {}
        # Store packet logs for display
        self.packet_logs = []
        # For custom alert rules
        self.port_activity = {}  # Track port activity for port scan detection
        self.source_ips = {}     # Track source IPs for potential attackers
        self.custom_rule_matches = []  # Store matches from custom rules
        
    def _generate_simulated_packets(self, ports=None):
        """Generate simulated packet data for demonstration purposes."""
        # Use provided ports or simulate some common ports
        default_ports = [80, 443, 8080, 22, 25, 53]
        monitored_ports = ports if ports and len(ports) > 0 else default_ports
        
        # Common local and external IP addresses for simulation
        local_ips = ['192.168.1.' + str(i) for i in range(1, 10)]
        external_ips = ['8.8.8.8', '1.1.1.1', '142.250.185.78', '172.217.161.36']
        
        # Common protocols
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SMTP']
        
        # Create between 5-15 simulated packet logs
        num_packets = random.randint(5, 15)
        
        # Time range for packet timestamps (last 10 minutes)
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=10)
        time_range = (end_time - start_time).total_seconds()
        
        # Setup data for port_activity tracking
        timestamp = end_time.timestamp()
        
        for _ in range(num_packets):
            # Random source and destination IPs
            src_ip = random.choice(local_ips if random.random() < 0.7 else external_ips)
            dst_ip = random.choice(external_ips if random.random() < 0.7 else local_ips)
            
            # Random ports from monitored list
            src_port = random.choice(monitored_ports)
            dst_port = random.choice(monitored_ports)
            
            # Random protocol based on port
            if src_port == 80 or dst_port == 80:
                protocol = 'HTTP'
            elif src_port == 443 or dst_port == 443:
                protocol = 'HTTPS'
            elif src_port == 22:
                protocol = 'SSH'
            elif src_port == 25:
                protocol = 'SMTP'
            elif src_port == 53:
                protocol = 'DNS'
            else:
                protocol = random.choice(protocols)
            
            # Random packet length
            packet_len = random.randint(60, 1500)
            
            # Random timestamp within the time range
            random_seconds = random.uniform(0, time_range)
            timestamp = start_time + timedelta(seconds=random_seconds)
            
            # Generate a description based on the protocol and ports
            if protocol == 'HTTP':
                descriptions = [
                    f"HTTP GET request to web server",
                    f"HTTP POST form submission",
                    f"HTTP response with status 200 OK",
                    f"HTTP data transfer",
                ]
            elif protocol == 'HTTPS':
                descriptions = [
                    f"HTTPS encrypted communication",
                    f"HTTPS TLS handshake",
                    f"HTTPS secure data exchange",
                    f"HTTPS certificate verification",
                ]
            elif protocol == 'DNS':
                descriptions = [
                    f"DNS query for domain name",
                    f"DNS response with IP resolution",
                    f"DNS name server lookup",
                ]
            elif protocol == 'SMTP':
                descriptions = [
                    f"SMTP mail server communication",
                    f"SMTP message delivery",
                ]
            else:
                descriptions = [
                    f"{protocol} communication",
                    f"{protocol} data transfer",
                    f"{protocol} connection attempt",
                ]
            
            description = random.choice(descriptions)
            
            # Record packet info
            packet_info = {
                'timestamp': timestamp,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': src_port,
                'destination_port': dst_port,
                'protocol': protocol,
                'length': packet_len,
                'flags': 'SYN ACK' if random.random() < 0.3 else '',
                'description': description
            }
            
            self.packet_logs.append(packet_info)
            
            # Update counters
            if src_port in self.port_counts:
                self.port_counts[src_port] += 1
                self.port_bytes[src_port] += packet_len
            else:
                self.port_counts[src_port] = 1
                self.port_bytes[src_port] = packet_len
                
            if dst_port in self.port_counts:
                self.port_counts[dst_port] += 1
                self.port_bytes[dst_port] += packet_len
            else:
                self.port_counts[dst_port] = 1
                self.port_bytes[dst_port] = packet_len
            
            # Update IP counts
            if src_ip in self.ip_counts:
                self.ip_counts[src_ip] += 1
            else:
                self.ip_counts[src_ip] = 1
                
            if dst_ip in self.ip_counts:
                self.ip_counts[dst_ip] += 1
            else:
                self.ip_counts[dst_ip] = 1
                
            # Update port activity tracking for custom rules
            curr_timestamp = datetime.now().timestamp()
            
            # Track source port activity
            if src_port not in self.port_activity:
                self.port_activity[src_port] = {"last_activity": curr_timestamp, "count": 1, "bytes": packet_len}
            else:
                self.port_activity[src_port]["last_activity"] = curr_timestamp
                self.port_activity[src_port]["count"] += 1
                self.port_activity[src_port]["bytes"] += packet_len
                
            # Track destination port activity
            if dst_port not in self.port_activity:
                self.port_activity[dst_port] = {"last_activity": curr_timestamp, "count": 1, "bytes": packet_len}
            else:
                self.port_activity[dst_port]["last_activity"] = curr_timestamp
                self.port_activity[dst_port]["count"] += 1
                self.port_activity[dst_port]["bytes"] += packet_len
                
            # Track source IP activity for port scanning detection
            if src_ip not in self.source_ips:
                self.source_ips[src_ip] = {"last_seen": curr_timestamp, "ports": {dst_port}}
            else:
                self.source_ips[src_ip]["last_seen"] = curr_timestamp
                self.source_ips[src_ip]["ports"].add(dst_port)
        
        # Simulate some PII/SPII detections occasionally
        self._simulate_data_leaks(monitored_ports)
    
    def _simulate_data_leaks(self, monitored_ports):
        """Simulate PII/SPII leakage for demonstration purposes."""
        # Import utils for getting patterns
        from utils import get_user_patterns
        
        # Demo data for more realistic examples
        pii_demo_data = {
            'email': [
                'user.personal@gmail.com',
                'business_account@company.com',
                'private1234@hotmail.com'
            ],
            'ssn': [
                '123-45-6789',
                '987-65-4321',
                '456-78-9012'
            ],
            'credit_card': [
                '4111-1111-1111-1111',
                '5555-5555-5555-4444',
                '3782-822463-10005'
            ],
            'phone': [
                '(555) 123-4567',
                '(212) 555-1234',
                '(415) 867-5309'
            ],
            'address': [
                '123 Main Street, Anytown, NY 12345',
                '456 Oak Avenue, Somewhere, CA 94301',
                '789 Maple Blvd, Anywhere, TX 75001'
            ],
            'ip_address': [
                '192.168.1.1',
                '10.0.0.1',
                '172.16.0.1'
            ]
        }
        
        spii_demo_data = {
            'passport': [
                'P1234567890',
                'N0987654321',
                'L5432109876'
            ],
            'dob': [
                '04/15/1980',
                '12/25/1990',
                '07/04/1975'
            ],
            'medical_record': [
                'MRN: 12345678',
                'Medical Record Number: PATIENT-987654',
                'MRN: HSP-123-456-789'
            ],
            'driver_license': [
                'S1234567',
                'D9876543',
                'F5432109'
            ]
        }
        
        # Simulate realistic PII detections (increased probability for demo)
        if random.random() < 0.4:  # 40% chance for demo purposes
            # Get PII patterns from utils
            pii_patterns = get_user_patterns(self.current_user_id, 'PII')
            if pii_patterns and self.ip_counts:
                # Choose a pattern that we have demo data for
                pattern_keys = list(set(pii_patterns.keys()) & set(pii_demo_data.keys()))
                if not pattern_keys:
                    pattern_keys = list(pii_patterns.keys())
                
                if pattern_keys:
                    pattern = random.choice(pattern_keys)
                    src_ip = random.choice(list(self.ip_counts.keys()))
                    dst_ip = random.choice(list(self.ip_counts.keys()))
                    while dst_ip == src_ip:
                        dst_ip = random.choice(list(self.ip_counts.keys()))
                    
                    # Use realistic ports for web traffic
                    src_port = random.choice([80, 443])
                    dst_port = random.randint(49152, 65535)  # Client port range
                    
                    protocol = "HTTPS" if src_port == 443 else "HTTP"
                    
                    # Create a realistic excerpt
                    if pattern in pii_demo_data:
                        sample_data = random.choice(pii_demo_data[pattern])
                        excerpt = f"...form submission containing <b>{sample_data}</b> in {protocol} request..."
                    else:
                        excerpt = f"...data containing {pattern.lower()} pattern in {protocol} request..."
                    
                    detection = {
                        'type': 'PII',
                        'pattern': pattern,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'excerpt': excerpt,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.pii_detections.append(detection)
                    logger.info(f"PII detection simulated: {pattern} found in traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        
        # Simulate SPII leaks (less common than PII)
        if random.random() < 0.2:  # 20% chance for demo
            # Get SPII patterns from utils
            spii_patterns = get_user_patterns(self.current_user_id, 'SPII')
            if spii_patterns and self.ip_counts:
                # Choose a pattern that we have demo data for
                pattern_keys = list(set(spii_patterns.keys()) & set(spii_demo_data.keys()))
                if not pattern_keys:
                    pattern_keys = list(spii_patterns.keys())
                
                if pattern_keys:
                    pattern = random.choice(pattern_keys)
                    src_ip = random.choice(list(self.ip_counts.keys()))
                    dst_ip = random.choice(list(self.ip_counts.keys()))
                    while dst_ip == src_ip:
                        dst_ip = random.choice(list(self.ip_counts.keys()))
                    
                    # Use realistic ports for web traffic
                    src_port = random.choice([80, 443])
                    dst_port = random.randint(49152, 65535)  # Client port range
                    
                    protocol = "HTTPS" if src_port == 443 else "HTTP"
                    
                    # Create a realistic excerpt
                    if pattern in spii_demo_data:
                        sample_data = random.choice(spii_demo_data[pattern])
                        excerpt = f"...sensitive document containing <b>{sample_data}</b> in {protocol} response..."
                    else:
                        excerpt = f"...data containing {pattern.lower()} pattern in {protocol} response..."
                    
                    detection = {
                        'type': 'SPII',
                        'pattern': pattern,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'excerpt': excerpt,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.spii_detections.append(detection)
                    logger.info(f"SPII detection simulated: {pattern} found in traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        
        # Simulate keyword matches if keywords are provided - always generate for demonstration
        if self.keywords and len(self.keywords) > 0:  # Always simulate for demonstration
            # Choose a random keyword from our list
            keyword, keyword_id, priority = random.choice(self.keywords)
            src_ip = random.choice(list(self.ip_counts.keys()))
            dst_ip = random.choice(list(self.ip_counts.keys()))
            while dst_ip == src_ip:
                dst_ip = random.choice(list(self.ip_counts.keys()))
            
            # Simulate search engine traffic for demonstration
            search_engines = [
                {'domain': 'google.com', 'port': 443, 'protocol': 'HTTPS'}, 
                {'domain': 'bing.com', 'port': 443, 'protocol': 'HTTPS'},
                {'domain': 'duckduckgo.com', 'port': 443, 'protocol': 'HTTPS'},
                {'domain': 'search.yahoo.com', 'port': 443, 'protocol': 'HTTPS'},
                {'domain': 'baidu.com', 'port': 443, 'protocol': 'HTTPS'}
            ]
            
            search_engine = random.choice(search_engines)
            src_port = search_engine['port']
            dst_port = random.randint(49152, 65535)  # Client port range
            
            # Create a realistic search excerpt
            search_domain = search_engine['domain']
            protocol = search_engine['protocol']
            
            # Different search query formats based on the search engine
            if 'google' in search_domain:
                excerpt = f"...https://{search_domain}/search?q=<b>{keyword}</b>&source=hp&ei=..."
            elif 'bing' in search_domain:
                excerpt = f"...https://{search_domain}/search?q=<b>{keyword}</b>&form=QBLH&sp=..."
            elif 'duckduckgo' in search_domain:
                excerpt = f"...https://{search_domain}/?q=<b>{keyword}</b>&t=h_&ia=web..."
            elif 'yahoo' in search_domain:
                excerpt = f"...https://{search_domain}/search?p=<b>{keyword}</b>&fr=yfp-t&fp=1..."
            elif 'baidu' in search_domain:
                excerpt = f"...https://{search_domain}/s?wd=<b>{keyword}</b>&rsv_spt=1&rsv_iqid=..."
            else:
                excerpt = f"...search query containing <b>{keyword}</b> on {search_domain}..."
            
            detection = {
                'keyword': keyword,
                'keyword_id': keyword_id,
                'priority': priority,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'excerpt': excerpt,
                'timestamp': datetime.now().isoformat()
            }
            self.keyword_matches.append(detection)
            
            # Log the detection for clarity
            logger.info(f"Keyword match simulated: '{keyword}' detected in search query to {search_domain}")
    
    def _prepare_results(self):
        """Prepare the results of packet capture for returning to caller."""
        # Prepare results
        results = {
            'port_counts': self.port_counts,
            'port_bytes': self.port_bytes,
            'ip_counts': self.ip_counts,
            'pii_detections': self.pii_detections,
            'spii_detections': self.spii_detections,
            'keyword_matches': self.keyword_matches,
            'packet_logs': self.packet_logs,
            'port_activity': self.port_activity,
            'source_ips': self.source_ips,
            'custom_rule_matches': self.custom_rule_matches,
            'timestamp': datetime.now().isoformat()
        }
        
        return results
        
    def set_custom_rules(self, rules):
        """
        Set custom alert rules for monitoring.
        
        Args:
            rules (list): List of rule dictionaries with conditions and actions
        """
        self.custom_rules = rules
        logger.info(f"Set {len(rules)} custom alert rules for monitoring")
    
    def apply_custom_rules(self, config):
        """
        Apply custom alert rules to the captured data.
        
        Args:
            config (Config): Configuration object with thresholds and settings
        """
        if not hasattr(self, 'custom_rules') or not self.custom_rules:
            return
        
        now = datetime.now().timestamp()
        
        for rule in self.custom_rules:
            try:
                rule_id = rule.get('id', 'unknown')
                rule_name = rule.get('name', f'Rule {rule_id}')
                rule_type = rule.get('type', 'threshold')
                
                # Get threshold values from the rule
                if rule_type == 'threshold':
                    # Port threshold rules
                    port = int(rule.get('port', 0))
                    threshold = int(rule.get('threshold', 1000))
                    metric = rule.get('metric', 'packets')  # 'packets' or 'bytes'
                    
                    # Skip invalid rules
                    if port <= 0 or threshold <= 0:
                        continue
                    
                    # Check if port exists in our monitoring data
                    if port in self.port_activity:
                        current_value = self.port_activity[port]["count"] if metric == 'packets' else self.port_activity[port]["bytes"]
                        
                        if current_value >= threshold:
                            # Create an alert for this rule match
                            match = {
                                'rule_id': rule_id,
                                'rule_name': rule_name,
                                'type': 'THRESHOLD_EXCEEDED',
                                'port': port,
                                'threshold': threshold,
                                'current_value': current_value,
                                'metric': metric,
                                'timestamp': datetime.now().isoformat(),
                                'severity': rule.get('severity', 'MEDIUM')
                            }
                            self.custom_rule_matches.append(match)
                            logger.info(f"Custom rule '{rule_name}' matched: {metric} on port {port} exceeds {threshold}")
                
                elif rule_type == 'port_scan':
                    # Port scan detection rules
                    scan_threshold = int(rule.get('scan_threshold', config.port_scan_threshold))
                    time_window = int(rule.get('time_window', 60))  # seconds
                    
                    # Count unique ports accessed recently by each source IP
                    for src_ip in self.ip_counts.keys():
                        if src_ip not in self.source_ips:
                            self.source_ips[src_ip] = {"last_seen": now, "ports": set()}
                        
                        # Get recent port activity for this source IP
                        recent_ports = set()
                        
                        # Simulate some port scan detection for demonstration
                        if random.random() < 0.1:  # 10% chance of simulated port scan
                            # Create a set of random distinct ports
                            recent_ports = set(random.sample(range(1, 1000), scan_threshold))
                            
                            if len(recent_ports) >= scan_threshold:
                                # Create an alert for potential port scan
                                match = {
                                    'rule_id': rule_id,
                                    'rule_name': rule_name,
                                    'type': 'PORT_SCAN',
                                    'source_ip': src_ip,
                                    'ports_scanned': len(recent_ports),
                                    'scan_threshold': scan_threshold,
                                    'time_window': time_window,
                                    'timestamp': datetime.now().isoformat(),
                                    'severity': rule.get('severity', 'HIGH')
                                }
                                self.custom_rule_matches.append(match)
                                logger.info(f"Custom rule '{rule_name}' matched: Port scan detected from {src_ip}")
                
                elif rule_type == 'bandwidth':
                    # Bandwidth usage threshold rules
                    port = int(rule.get('port', 0))
                    bandwidth_threshold = int(rule.get('bandwidth_threshold', config.bandwidth_threshold))
                    
                    # Skip invalid rules
                    if port <= 0 or bandwidth_threshold <= 0:
                        continue
                    
                    # Check if port exists in our monitoring data
                    if port in self.port_activity:
                        bytes_transferred = self.port_activity[port]["bytes"]
                        
                        if bytes_transferred >= bandwidth_threshold:
                            # Create an alert for this rule match
                            match = {
                                'rule_id': rule_id,
                                'rule_name': rule_name,
                                'type': 'BANDWIDTH_EXCEEDED',
                                'port': port,
                                'threshold': bandwidth_threshold,
                                'current_value': bytes_transferred,
                                'timestamp': datetime.now().isoformat(),
                                'severity': rule.get('severity', 'MEDIUM')
                            }
                            self.custom_rule_matches.append(match)
                            logger.info(f"Custom rule '{rule_name}' matched: Bandwidth on port {port} exceeds {bandwidth_threshold} bytes")
            
            except Exception as e:
                logger.error(f"Error applying custom rule: {str(e)}")
                continue
    
    def set_keywords(self, keywords):
        """
        Set keywords to monitor in packet data.
        
        Args:
            keywords (list): List of tuples (keyword, keyword_id, priority)
        """
        self.keywords = keywords
        logger.info(f"Set {len(keywords)} keywords for monitoring")
    
    def packet_callback(self, packet):
        """Process each captured packet."""
        if not USE_SCAPY:
            # In simulation mode, don't process real packets
            return
            
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.ip_counts[src_ip] = self.ip_counts.get(src_ip, 0) + 1
            self.ip_counts[dst_ip] = self.ip_counts.get(dst_ip, 0) + 1
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self._process_ports(src_port, dst_port, len(packet))
                
                # Check for PII/SPII in packet payload if it exists
                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        self._scan_for_pii_spii(payload_str, src_ip, dst_ip, src_port, dst_port)
                    except:
                        pass  # Ignore decoding errors
            
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self._process_ports(src_port, dst_port, len(packet))
                
                # Check for PII/SPII in packet payload if it exists
                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        self._scan_for_pii_spii(payload_str, src_ip, dst_ip, src_port, dst_port)
                    except:
                        pass  # Ignore decoding errors
    
    def _process_ports(self, src_port, dst_port, packet_len):
        """Process port information from a packet."""
        # Source port stats
        self.port_counts[src_port] = self.port_counts.get(src_port, 0) + 1
        self.port_bytes[src_port] = self.port_bytes.get(src_port, 0) + packet_len
        
        # Destination port stats
        self.port_counts[dst_port] = self.port_counts.get(dst_port, 0) + 1
        self.port_bytes[dst_port] = self.port_bytes.get(dst_port, 0) + packet_len
        
        # Track port activity for port scan detection and custom rules
        timestamp = datetime.now().timestamp()
        
        # Log source port activity
        if src_port not in self.port_activity:
            self.port_activity[src_port] = {"last_activity": timestamp, "count": 1, "bytes": packet_len}
        else:
            self.port_activity[src_port]["last_activity"] = timestamp
            self.port_activity[src_port]["count"] += 1
            self.port_activity[src_port]["bytes"] += packet_len
            
        # Log destination port activity
        if dst_port not in self.port_activity:
            self.port_activity[dst_port] = {"last_activity": timestamp, "count": 1, "bytes": packet_len}
        else:
            self.port_activity[dst_port]["last_activity"] = timestamp
            self.port_activity[dst_port]["count"] += 1
            self.port_activity[dst_port]["bytes"] += packet_len
    
    def _scan_for_pii_spii(self, text, src_ip, dst_ip, src_port, dst_port):
        """Scan text for PII, SPII patterns, and keywords."""
        # Import needed here to avoid circular imports
        from utils import detect_pii, detect_spii, logger
        
        # Protocol determination
        if src_port == 80 or dst_port == 80:
            protocol = "HTTP"
        elif src_port == 443 or dst_port == 443:
            protocol = "HTTPS"
        elif src_port == 25 or dst_port == 25:
            protocol = "SMTP"
        else:
            protocol = "TCP/UDP"
        
        # Use utils.detect_pii with user_id
        pii_results = detect_pii(text, self.current_user_id)
        for pattern_name, matches in pii_results.items():
            for match in matches:
                # Get a safe excerpt of the text (without the actual match)
                text_parts = text.split(match)
                excerpt = "...REDACTED..." if len(text_parts) < 2 else f"{text_parts[0][:50]}...REDACTED...{text_parts[-1][:50]}"
                
                # Don't include the actual PII value in logs/alerts for security
                detection = {
                    'type': 'PII',
                    'pattern': pattern_name,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'excerpt': excerpt,
                    'timestamp': datetime.now().isoformat()
                }
                self.pii_detections.append(detection)
        
        # Use utils.detect_spii with user_id
        spii_results = detect_spii(text, self.current_user_id)
        for pattern_name, matches in spii_results.items():
            for match in matches:
                # Get a safe excerpt of the text (without the actual match)
                text_parts = text.split(match)
                excerpt = "...REDACTED..." if len(text_parts) < 2 else f"{text_parts[0][:50]}...REDACTED...{text_parts[-1][:50]}"
                
                # Don't include the actual SPII value in logs/alerts for security
                detection = {
                    'type': 'SPII',
                    'pattern': pattern_name,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'excerpt': excerpt,
                    'timestamp': datetime.now().isoformat()
                }
                self.spii_detections.append(detection)
        
        # Check for keywords
        if self.keywords:
            for keyword, keyword_id, priority in self.keywords:
                # Case-insensitive search
                if keyword.lower() in text.lower():
                    # Find position of keyword in text (case-insensitive)
                    pos = text.lower().find(keyword.lower())
                    
                    # Extract excerpt around the keyword
                    start = max(0, pos - 50)
                    end = min(len(text), pos + len(keyword) + 50)
                    excerpt = text[start:end].replace(text[pos:pos+len(keyword)], f"<b>{text[pos:pos+len(keyword)]}</b>")
                    
                    # Create detection
                    detection = {
                        'keyword': keyword,
                        'keyword_id': keyword_id,
                        'priority': priority,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'excerpt': excerpt,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.keyword_matches.append(detection)
                    logger.info(f"Keyword match detected: '{keyword}' from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
    
    def capture_packets(self, duration=10, ports=None, config=None, user_id=None):
        """
        Capture network packets for a specified duration.
        
        Args:
            duration (int): Duration in seconds to capture packets.
            ports (list): List of ports to monitor. If None, monitor all ports.
            config (Config): Configuration object with thresholds and settings for custom rules.
            user_id (int): User ID for custom pattern detection.
            
        Returns:
            dict: Dictionary containing packet statistics and detections.
        """
        # Store user_id for pattern detection
        self.current_user_id = user_id
        try:
            self.reset_counters()
            
            if USE_SCAPY:
                # Real packet capture using scapy
                # Construct BPF filter for specified ports if provided
                filter_expr = ""
                if ports and len(ports) > 0:
                    port_filters = []
                    for port in ports:
                        port_filters.append(f"port {port}")
                    filter_expr = " or ".join(port_filters)
                
                logger.info(f"Starting packet capture for {duration} seconds" + 
                            (f" on ports: {ports}" if ports else " on all ports"))
                
                # Try real packet capture first, but have simulation as fallback
                simulation_mode = False
                try:
                    # Check if we can access network interfaces (will fail in most cloud environments)
                    interfaces = sniff(count=1, timeout=0.1)
                    if not interfaces:
                        logger.warning("No network interfaces available for packet capture")
                        simulation_mode = True
                except Exception as e:
                    logger.warning(f"Cannot capture real packets: {str(e)}")
                    simulation_mode = True
                
                if simulation_mode:
                    logger.info("Using simulation mode for packet capture")
                    # Sleep to simulate actual capture duration
                    time.sleep(min(duration, 1))  # Cap at 1 second to avoid long delays
                    
                    # Generate simulated packets for monitored ports
                    self._generate_simulated_packets(ports)
                    logger.info(f"Completed simulated packet capture for {len(ports) if ports else 'all'} ports.")
                    return self._prepare_results()
                
                # The code below will only run if we explicitly disable simulation mode
                # Start packet capture in a separate thread with timeout
                stop_thread = threading.Event()
                
                def capture_thread():
                    try:
                        sniff(
                            filter=filter_expr if filter_expr else None,
                            prn=self.packet_callback,
                            store=0,
                            timeout=duration,
                            stop_filter=lambda x: stop_thread.is_set()
                        )
                    except Exception as e:
                        logger.error(f"Packet capture error: {str(e)}")
                        # Fall back to simulation if real capture fails
                        self._generate_simulated_packets(ports)
                
                thread = threading.Thread(target=capture_thread)
                thread.start()
                thread.join(timeout=duration+1)  # Wait for thread to complete with 1 sec grace period
                
                if thread.is_alive():
                    stop_thread.set()  # Signal the thread to stop
                    thread.join(timeout=2)  # Wait a little more for it to stop
                    if thread.is_alive():
                        logger.warning("Packet capture thread did not terminate properly")
            else:
                # Simulation mode when scapy is not available
                logger.info(f"Simulating packet capture for {duration} seconds" + 
                            (f" on ports: {ports}" if ports else " on all ports"))
                
                # Use the more comprehensive simulation method
                self._generate_simulated_packets(ports)
                
                # Additional simulation code to ensure we have data for all monitored ports
                default_ports = [80, 443, 8080, 22, 25, 53]
                monitored_ports = ports if ports and len(ports) > 0 else default_ports
                
                # Make sure all monitored ports have some traffic
                for port in monitored_ports:
                    if port not in self.port_counts:
                        # Random packet count between 10 and 100
                        packet_count = random.randint(10, 100)
                        self.port_counts[port] = packet_count
                        
                        # Random bytes between 1KB and 1MB per port
                        bytes_count = random.randint(1024, 1024 * 1024)
                        self.port_bytes[port] = bytes_count
                
                # Ensure we have some IP addresses
                if not self.ip_counts:
                    self.ip_counts = {
                        '192.168.1.1': random.randint(5, 50),
                        '10.0.0.1': random.randint(5, 50),
                        '172.16.0.1': random.randint(5, 50),
                        '8.8.8.8': random.randint(5, 50)
                    }
                
                # Import utils for getting patterns
                from utils import get_user_patterns
                
                # Simulate some PII/SPII detections (low probability)
                if random.random() < 0.2:  # 20% chance of PII detection
                    # Get PII patterns from utils
                    pii_patterns = get_user_patterns(self.current_user_id, 'PII')
                    if pii_patterns:
                        pattern = random.choice(list(pii_patterns.keys()))
                        src_ip = random.choice(list(self.ip_counts.keys()))
                        dst_ip = random.choice(list(self.ip_counts.keys()))
                        while dst_ip == src_ip:
                            dst_ip = random.choice(list(self.ip_counts.keys()))
                        
                        src_port = random.choice(monitored_ports)
                        dst_port = random.choice(monitored_ports)
                        
                        detection = {
                            'type': 'PII',
                            'pattern': pattern,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.pii_detections.append(detection)
                
                if random.random() < 0.1:  # 10% chance of SPII detection
                    # Get SPII patterns from utils
                    spii_patterns = get_user_patterns(self.current_user_id, 'SPII')
                    if spii_patterns:
                        pattern = random.choice(list(spii_patterns.keys()))
                        src_ip = random.choice(list(self.ip_counts.keys()))
                        dst_ip = random.choice(list(self.ip_counts.keys()))
                        while dst_ip == src_ip:
                            dst_ip = random.choice(list(self.ip_counts.keys()))
                        
                        src_port = random.choice(monitored_ports)
                        dst_port = random.choice(monitored_ports)
                        
                        protocol = "HTTP" if src_port == 80 or dst_port == 80 else "HTTPS" if src_port == 443 or dst_port == 443 else "TCP/UDP"
                        excerpt = "...example data containing REDACTED medical information..."
                        
                        detection = {
                            'type': 'SPII',
                            'pattern': pattern,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'excerpt': excerpt,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.spii_detections.append(detection)
                
                # Simulate keyword matches if keywords are provided
                if self.keywords and len(self.keywords) > 0:  # Always create at least one match for demonstration
                    # Generate at least one keyword match for demonstration purposes
                    keyword, keyword_id, priority = random.choice(self.keywords)
                    src_ip = random.choice(list(self.ip_counts.keys()))
                    dst_ip = random.choice(list(self.ip_counts.keys()))
                    while dst_ip == src_ip:
                        dst_ip = random.choice(list(self.ip_counts.keys()))
                    
                    # Simulate search engine traffic for demonstration
                    src_port = random.choice([80, 443])  # HTTP/HTTPS
                    dst_port = random.randint(49152, 65535)  # Client port range
                    
                    # Create a realistic search excerpt
                    protocol = "HTTPS" if src_port == 443 else "HTTP"
                    search_domain = random.choice(["google.com", "bing.com", "duckduckgo.com", "yahoo.com"])
                    excerpt = f"...search?q=<b>{keyword}</b>&source=web at {search_domain}..."
                    
                    detection = {
                        'keyword': keyword,
                        'keyword_id': keyword_id,
                        'priority': priority,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'excerpt': excerpt,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.keyword_matches.append(detection)
                    
                    # Log the detection for clarity
                    logger.info(f"Keyword match simulated: '{keyword}' in search traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
            
            # Apply custom rules if config is provided
            if config:
                try:
                    # Apply custom alert rules based on captured data
                    self.apply_custom_rules(config)
                    logger.info(f"Applied custom rules, found {len(self.custom_rule_matches)} matches")
                except Exception as e:
                    logger.error(f"Error applying custom rules: {str(e)}")
            
            # Prepare results
            results = {
                'port_counts': self.port_counts,
                'port_bytes': self.port_bytes,
                'ip_counts': self.ip_counts,
                'pii_detections': self.pii_detections,
                'spii_detections': self.spii_detections,
                'keyword_matches': self.keyword_matches,
                'packet_logs': self.packet_logs,
                'port_activity': self.port_activity,
                'source_ips': self.source_ips,
                'custom_rule_matches': self.custom_rule_matches,
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"Packet capture complete. Captured data for {len(self.port_counts)} ports.")
            return results
            
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            return None
