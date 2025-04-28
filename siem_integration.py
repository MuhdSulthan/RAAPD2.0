"""
SIEM Integration Module for RAAPD

This module provides connectors to export security events to common SIEM systems:
- Syslog (CEF/LEEF formats)
- Elastic Security
- Splunk
- Microsoft Sentinel
- Generic webhook for custom integrations

Usage:
    from siem_integration import SIEMExporter
    
    # Initialize with configs
    siem = SIEMExporter(configs)
    
    # Export an alert
    siem.export_alert(alert)
"""

import json
import logging
import requests
import socket
import time
from datetime import datetime
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# Format constants
FORMAT_CEF = 'cef'
FORMAT_LEEF = 'leef'
FORMAT_JSON = 'json'
FORMAT_ELASTIC = 'elastic'
FORMAT_SPLUNK = 'splunk'
FORMAT_SENTINEL = 'sentinel'

# Severity mapping
SEVERITY_MAP = {
    'LOW': 1,
    'MEDIUM': 5,
    'HIGH': 8,
    'CRITICAL': 10
}

class SIEMExporter:
    """Handles exporting security events to SIEM systems."""
    
    def __init__(self, config=None):
        """
        Initialize the SIEM exporter.
        
        Args:
            config (dict): Configuration for SIEM exports including:
                - enabled (bool): Whether SIEM integration is enabled
                - methods (list): Export methods to use (syslog, webhook, elastic, splunk, sentinel)
                - format (str): Format for exports (cef, leef, json)
                - syslog_host (str): Host for syslog server
                - syslog_port (int): Port for syslog server
                - webhook_url (str): URL for webhook exports
                - webhook_auth_header (str): Authorization header for webhook
                - elastic_url (str): URL for Elasticsearch
                - elastic_api_key (str): API key for Elasticsearch
                - splunk_url (str): URL for Splunk HEC
                - splunk_token (str): Token for Splunk HEC
                - sentinel_workspace_id (str): Microsoft Sentinel workspace ID
                - sentinel_shared_key (str): Microsoft Sentinel shared key
                - include_fields (list): Fields to include in exports
                - exclude_fields (list): Fields to exclude from exports
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        
        # Default export methods if not specified
        if 'methods' not in self.config:
            self.config['methods'] = ['syslog']
            
        # Default format if not specified
        if 'format' not in self.config:
            self.config['format'] = FORMAT_CEF
            
        # Initialize connections
        self._init_connections()
    
    def _init_connections(self):
        """Initialize connections to SIEM systems."""
        self.connections = {}
        
        # Syslog connection
        if 'syslog' in self.config.get('methods', []):
            try:
                self.connections['syslog'] = self._init_syslog()
                logger.info("Initialized syslog connection")
            except Exception as e:
                logger.error(f"Failed to initialize syslog connection: {str(e)}")
        
        # Other connections are initialized on-demand
    
    def _init_syslog(self):
        """Initialize syslog connection."""
        if not self.config.get('syslog_host'):
            return None
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return {
            'socket': sock,
            'host': self.config.get('syslog_host', 'localhost'),
            'port': int(self.config.get('syslog_port', 514))
        }
    
    def export_alert(self, alert):
        """
        Export an alert to configured SIEM systems.
        
        Args:
            alert (models.Alert): The alert to export
        
        Returns:
            dict: Status of exports to each method
        """
        if not self.enabled:
            logger.debug("SIEM exports disabled, skipping")
            return {'status': 'disabled'}
            
        results = {}
        
        # Get alert data as dictionary
        alert_data = alert.to_dict() if hasattr(alert, 'to_dict') else alert
        
        # Apply field filtering
        alert_data = self._filter_fields(alert_data)
        
        # Export via each configured method
        for method in self.config.get('methods', []):
            try:
                if method == 'syslog':
                    results['syslog'] = self._export_syslog(alert_data)
                elif method == 'webhook':
                    results['webhook'] = self._export_webhook(alert_data)
                elif method == 'elastic':
                    results['elastic'] = self._export_elastic(alert_data)
                elif method == 'splunk':
                    results['splunk'] = self._export_splunk(alert_data)
                elif method == 'sentinel':
                    results['sentinel'] = self._export_sentinel(alert_data)
            except Exception as e:
                logger.error(f"Failed to export alert to {method}: {str(e)}")
                results[method] = {'status': 'error', 'message': str(e)}
        
        return results
    
    def _filter_fields(self, data):
        """
        Filter alert data fields based on configuration.
        
        Args:
            data (dict): Alert data to filter
            
        Returns:
            dict: Filtered alert data
        """
        if not isinstance(data, dict):
            return data
            
        # Include specified fields only if include_fields is set
        if 'include_fields' in self.config and self.config['include_fields']:
            return {k: v for k, v in data.items() if k in self.config['include_fields']}
            
        # Otherwise, exclude specified fields if exclude_fields is set
        if 'exclude_fields' in self.config and self.config['exclude_fields']:
            return {k: v for k, v in data.items() if k not in self.config['exclude_fields']}
            
        # If neither is specified, return all fields
        return data
    
    def _format_data(self, data, format_type=None):
        """
        Format alert data for export.
        
        Args:
            data (dict): Alert data to format
            format_type (str): Format type to use (default: config format)
            
        Returns:
            str: Formatted alert data
        """
        format_type = format_type or self.config.get('format', FORMAT_CEF)
        
        if format_type == FORMAT_JSON:
            return json.dumps(data)
        elif format_type == FORMAT_CEF:
            return self._format_cef(data)
        elif format_type == FORMAT_LEEF:
            return self._format_leef(data)
        elif format_type == FORMAT_ELASTIC:
            return json.dumps(self._format_elastic(data))
        elif format_type == FORMAT_SPLUNK:
            return json.dumps(self._format_splunk(data))
        elif format_type == FORMAT_SENTINEL:
            return json.dumps(self._format_sentinel(data))
        else:
            return json.dumps(data)
    
    def _format_cef(self, data):
        """Format alert data in CEF format."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        
        # Get basic alert properties
        device_vendor = "RAAPD"
        device_product = "NetworkMonitor"
        device_version = "1.0"
        signature_id = data.get('id', 0)
        alert_type = data.get('alert_type', 'UNKNOWN')
        severity = SEVERITY_MAP.get(data.get('severity', 'MEDIUM'), 5)
        
        # Build extension
        extension = {
            'msg': data.get('message', 'No message'),
            'src': data.get('source_ip', '0.0.0.0'),
            'dst': data.get('destination_ip', '0.0.0.0'),
            'spt': data.get('port', 0),
            'dpt': data.get('port', 0),
            'proto': data.get('protocol', 'UNKNOWN'),
        }
        
        ext_str = " ".join([f"{k}={v}" for k, v in extension.items()])
        
        return f"CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|{alert_type}|{severity}|{ext_str}"
    
    def _format_leef(self, data):
        """Format alert data in LEEF format."""
        # LEEF:Version|Vendor|Product|Version|EventID|Extension
        
        # Get basic alert properties
        vendor = "RAAPD"
        product = "NetworkMonitor"
        version = "1.0"
        event_id = data.get('id', 0)
        
        # Build extension
        extension = {
            'cat': data.get('alert_type', 'UNKNOWN'),
            'sev': SEVERITY_MAP.get(data.get('severity', 'MEDIUM'), 5),
            'msg': data.get('message', 'No message'),
            'src': data.get('source_ip', '0.0.0.0'),
            'dst': data.get('destination_ip', '0.0.0.0'),
            'srcPort': data.get('port', 0),
            'dstPort': data.get('port', 0),
            'proto': data.get('protocol', 'UNKNOWN'),
            'usrName': data.get('user_id', 'unknown')
        }
        
        ext_str = "\t".join([f"{k}={v}" for k, v in extension.items()])
        
        return f"LEEF:1.0|{vendor}|{product}|{version}|{event_id}|{ext_str}"
    
    def _format_elastic(self, data):
        """Format data for Elasticsearch."""
        # Add necessary Elasticsearch fields
        elastic_data = data.copy()
        elastic_data['@timestamp'] = data.get('timestamp', datetime.utcnow().isoformat())
        elastic_data['event'] = {
            'kind': 'alert',
            'category': 'network',
            'type': data.get('alert_type', 'unknown').lower(),
            'severity': SEVERITY_MAP.get(data.get('severity', 'MEDIUM'), 5)
        }
        
        # Add host and source info
        elastic_data['host'] = {
            'name': socket.gethostname()
        }
        elastic_data['source'] = {
            'ip': data.get('source_ip', '0.0.0.0')
        }
        elastic_data['destination'] = {
            'ip': data.get('destination_ip', '0.0.0.0')
        }
        
        return elastic_data
    
    def _format_splunk(self, data):
        """Format data for Splunk HEC."""
        # Format for Splunk HTTP Event Collector
        return {
            'time': int(time.time()),
            'host': socket.gethostname(),
            'source': 'raapd_network_monitor',
            'sourcetype': 'raapd:alert',
            'index': 'security',
            'event': data
        }
    
    def _format_sentinel(self, data):
        """Format data for Microsoft Sentinel."""
        # Basic format for Log Analytics
        return {
            'LogName': 'RAAPD_NetworkAlert',
            'TimeGenerated': data.get('timestamp', datetime.utcnow().isoformat()),
            'AlertType': data.get('alert_type', 'UNKNOWN'),
            'Severity': data.get('severity', 'MEDIUM'),
            'SourceIP': data.get('source_ip', '0.0.0.0'),
            'DestinationIP': data.get('destination_ip', '0.0.0.0'),
            'Protocol': data.get('protocol', 'UNKNOWN'),
            'Message': data.get('message', 'No message'),
            'UserID': data.get('user_id', 0)
        }
    
    def _export_syslog(self, data):
        """Export alert to syslog."""
        if 'syslog' not in self.connections or not self.connections['syslog']:
            self.connections['syslog'] = self._init_syslog()
            
        if not self.connections['syslog']:
            return {'status': 'error', 'message': 'Syslog connection not available'}
            
        # Format data based on configured format
        message = self._format_data(data)
        
        # Send to syslog server
        sock = self.connections['syslog']['socket']
        host = self.connections['syslog']['host']
        port = self.connections['syslog']['port']
        
        sock.sendto(message.encode(), (host, port))
        
        return {'status': 'success', 'server': f"{host}:{port}"}
    
    def _export_webhook(self, data):
        """Export alert via webhook."""
        webhook_url = self.config.get('webhook_url')
        if not webhook_url:
            return {'status': 'error', 'message': 'Webhook URL not configured'}
        
        # Format data as JSON
        payload = self._format_data(data, FORMAT_JSON)
        
        # Set up headers
        headers = {
            'Content-Type': 'application/json'
        }
        
        # Add authorization header if configured
        auth_header = self.config.get('webhook_auth_header')
        if auth_header:
            headers['Authorization'] = auth_header
        
        # Send to webhook
        response = requests.post(webhook_url, data=payload, headers=headers)
        
        if response.status_code >= 200 and response.status_code < 300:
            return {'status': 'success', 'code': response.status_code}
        else:
            return {
                'status': 'error', 
                'code': response.status_code,
                'message': response.text
            }
    
    def _export_elastic(self, data):
        """Export alert to Elasticsearch."""
        elastic_url = self.config.get('elastic_url')
        if not elastic_url:
            return {'status': 'error', 'message': 'Elasticsearch URL not configured'}
        
        # Format data for Elasticsearch
        payload = self._format_data(data, FORMAT_ELASTIC)
        
        # Set up headers
        headers = {
            'Content-Type': 'application/json'
        }
        
        # Add API key if configured
        api_key = self.config.get('elastic_api_key')
        if api_key:
            headers['Authorization'] = f"ApiKey {api_key}"
        
        # Construct URL for the security index
        index_url = urljoin(elastic_url, '/_security/alerts/_doc')
        
        # Send to Elasticsearch
        response = requests.post(index_url, data=payload, headers=headers)
        
        if response.status_code >= 200 and response.status_code < 300:
            return {'status': 'success', 'code': response.status_code}
        else:
            return {
                'status': 'error', 
                'code': response.status_code,
                'message': response.text
            }
    
    def _export_splunk(self, data):
        """Export alert to Splunk."""
        splunk_url = self.config.get('splunk_url')
        splunk_token = self.config.get('splunk_token')
        
        if not splunk_url or not splunk_token:
            return {'status': 'error', 'message': 'Splunk URL or token not configured'}
        
        # Format data for Splunk HEC
        payload = self._format_data(data, FORMAT_SPLUNK)
        
        # Set up headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Splunk {splunk_token}"
        }
        
        # Send to Splunk
        response = requests.post(splunk_url, data=payload, headers=headers)
        
        if response.status_code >= 200 and response.status_code < 300:
            return {'status': 'success', 'code': response.status_code}
        else:
            return {
                'status': 'error', 
                'code': response.status_code,
                'message': response.text
            }
    
    def _export_sentinel(self, data):
        """Export alert to Microsoft Sentinel."""
        workspace_id = self.config.get('sentinel_workspace_id')
        shared_key = self.config.get('sentinel_shared_key')
        
        if not workspace_id or not shared_key:
            return {'status': 'error', 'message': 'Sentinel workspace ID or shared key not configured'}
        
        # Format data for Sentinel
        payload = self._format_data(data, FORMAT_SENTINEL)
        
        # Build URL
        url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        
        # TODO: Implement Sentinel authentication signature
        
        # For now, just return a placeholder
        return {'status': 'not_implemented', 'message': 'Microsoft Sentinel integration not fully implemented'}