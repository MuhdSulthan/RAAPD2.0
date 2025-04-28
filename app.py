import os
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from apscheduler.schedulers.background import BackgroundScheduler
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TelField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Optional
from utils import send_sms, send_ntfy_notification, port_service_name
import atexit

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
mail = Mail()
bcrypt = Bcrypt()

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# GMT+6 timezone
GMT6 = timezone(timedelta(hours=6))

# Function to convert UTC time to GMT+6
def utc_to_gmt6(utc_dt):
    """Convert UTC datetime to GMT+6 timezone"""
    if utc_dt is None:
        return None
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    return utc_dt.astimezone(GMT6)

# Make the time conversion function available to all templates
@app.context_processor
def inject_utc_to_gmt6():
    from datetime import datetime
    return {'utc_to_gmt6': utc_to_gmt6, 'datetime': datetime}

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///raapd.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure Flask-Login
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@raapd.com')
mail.init_app(app)

# Initialize Bcrypt
bcrypt.init_app(app)

# Initialize the app with the extension
db.init_app(app)

# Import modules after initializing app and db
from models import Alert, NetworkStats, Config, User, Keyword, PacketLog
from analyzer import NetworkAnalyzer
from detector import AnomalyDetector

# Initialize the network analyzer and anomaly detector
analyzer = NetworkAnalyzer()
detector = AnomalyDetector()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Process alert notifications (email and ntfy.sh)
def process_notifications(alert):
    """
    Process notifications for a new alert using email and ntfy.sh.
    All notifications (email, SMS-style, and direct ntfy.sh) are sent based on
    user preferences. SMS-style alerts are sent via ntfy.sh - Twilio is not used.
    
    Args:
        alert (Alert): The alert to notify about
    """
    try:
        # Get users who need to be notified based on the alert type
        # Only notify users who have the global notifications switch enabled
        query = User.query.filter(User.is_active == True, User.notifications_enabled == True)
        
        # Filter by alert preferences
        if alert.alert_type == "PII_LEAK":
            query = query.filter(User.alert_on_pii == True)
        elif alert.alert_type == "SPII_LEAK":
            query = query.filter(User.alert_on_spii == True)
        elif alert.alert_type == "TRAFFIC_ANOMALY":
            query = query.filter(User.alert_on_anomaly == True)
        elif alert.alert_type == "KEYWORD_MATCH":
            query = query.filter(User.alert_on_keywords == True)
        
        # Get list of users to notify
        users = query.all()
        
        # No users to notify
        if not users:
            logger.warning(f"No users to notify for alert ID {alert.id}")
            return
        
        # Alert message
        alert_message = f"RAAPD Alert ({alert.severity}): {alert.message}"
        if alert.source_ip:
            alert_message += f" | Source: {alert.source_ip}"
        if alert.destination_ip:
            alert_message += f" | Destination: {alert.destination_ip}"
        if alert.port:
            alert_message += f" | Port: {alert.port}"
        
        # Notify each user according to their preferences
        for user in users:
            # Set user ID for this alert
            if alert.user_id is None:
                alert.user_id = user.id
            
            # Send email notification
            if user.email_alerts and user.email and not alert.email_sent:
                try:
                    msg = Message(
                        subject=f"RAAPD Security Alert: {alert.alert_type}",
                        recipients=[user.email],
                        body=alert_message
                    )
                    mail.send(msg)
                    alert.email_sent = True
                    logger.info(f"Email alert sent to {user.email} for alert ID {alert.id}")
                except Exception as e:
                    logger.error(f"Failed to send email to {user.email}: {str(e)}")
            
            # Parse user's preferred ntfy servers if available
            preferred_servers = None
            if hasattr(user, 'ntfy_servers') and user.ntfy_servers:
                try:
                    import json
                    preferred_servers = json.loads(user.ntfy_servers)
                    if preferred_servers and isinstance(preferred_servers, list):
                        logger.info(f"Using {len(preferred_servers)} preferred ntfy servers for user {user.id}")
                except Exception as e:
                    logger.error(f"Failed to parse ntfy_servers for user {user.id}: {str(e)}")
                
            # Send SMS-style alerts via ntfy.sh (not actual SMS - Twilio completely removed)
            if user.sms_alerts and user.phone and not alert.sms_sent:
                success = send_sms(user.phone, alert_message, preferred_servers=preferred_servers)  # This now uses ntfy.sh internally
                if success:
                    alert.sms_sent = True
                    logger.info(f"SMS-style alert sent via ntfy.sh for user with phone {user.phone}, alert ID {alert.id}")
            
            # Send ntfy.sh notification
            if user.ntfy_alerts and user.ntfy_topic and not alert.ntfy_sent:
                # Determine appropriate tags and priority based on alert severity
                if alert.severity == "CRITICAL" or alert.severity == "HIGH":
                    priority = "high"
                    tags = ["warning", "shield", "rotating_light"]
                elif alert.severity == "MEDIUM":
                    priority = "default"
                    tags = ["warning", "shield"]
                else:  # LOW
                    priority = "low"
                    tags = ["shield", "information_source"]
                
                # Add specific icon based on alert type
                if alert.alert_type == "PII_LEAK":
                    tags.append("lock")
                elif alert.alert_type == "SPII_LEAK":
                    tags.append("lock_with_ink_pen")
                elif alert.alert_type == "TRAFFIC_ANOMALY":
                    tags.append("chart_with_upwards_trend")
                elif alert.alert_type == "KEYWORD_MATCH":
                    tags.append("mag")
                
                # Send notification
                success = send_ntfy_notification(
                    topic=user.ntfy_topic,
                    title=f"RAAPD Alert: {alert.alert_type}",
                    message=alert_message,
                    priority=priority,
                    tags=tags,
                    preferred_servers=preferred_servers
                )
                
                if success:
                    alert.ntfy_sent = True
                    logger.info(f"ntfy.sh alert sent to topic {user.ntfy_topic} for alert ID {alert.id}")
                
                # SIEM integration - Export alert to configured SIEM systems
                try:
                    # Get user's config for SIEM integrations
                    config = Config.query.filter_by(user_id=user.id).first()
                    if config:
                        # Check if SIEM integration is enabled
                        try:
                            siem_config = config.get_siem_config()
                            if siem_config and siem_config.get('enabled', False):
                                # Import SIEM exporter
                                from siem_integration import SIEMExporter
                                
                                # Initialize exporter with configuration
                                exporter = SIEMExporter(siem_config)
                                
                                # Export the alert
                                export_results = exporter.export_alert(alert)
                                
                                # Log export status
                                logger.info(f"SIEM export results for alert {alert.id}: {export_results}")
                                
                                # Store export records in database
                                for method, result in export_results.items():
                                    if method != 'status':  # Skip the overall status
                                        # Create export record
                                        export = SIEMExport(
                                            alert_id=alert.id,
                                            user_id=user.id,
                                            export_method=method,
                                            export_status='success' if result.get('status') == 'success' else 'error',
                                            export_destination=result.get('server') or result.get('url') or '',
                                            response_data=json.dumps(result)
                                        )
                                        db.session.add(export)
                                
                                logger.info(f"SIEM exports registered for alert {alert.id}")
                        except Exception as e:
                            logger.error(f"Error parsing SIEM config for user {user.id}: {str(e)}")
                except Exception as e:
                    logger.error(f"Failed to process SIEM exports: {str(e)}")
        
        # Update the alert in the database
        db.session.commit()
            
    except Exception as e:
        logger.error(f"Error processing notifications: {str(e)}")
        db.session.rollback()

# Background task to analyze network traffic
def analyze_network_traffic():
    with app.app_context():
        try:
            # Get all active users with their configurations
            users = User.query.filter_by(is_active=True).all()
            if not users:
                logger.warning("No active users found. Skipping network analysis.")
                return
                
            # Process each user's configuration
            for user in users:
                # Get user's configuration
                config = Config.query.filter_by(user_id=user.id).first()
                if not config:
                    logger.warning(f"No configuration found for user {user.id}. Using defaults.")
                    monitored_ports = [80, 443, 8080]
                    monitoring_active = True
                    pii_patterns = True
                    spii_patterns = True
                else:
                    monitored_ports = [int(port.strip()) for port in config.monitored_ports.split(',') if port.strip()]
                    monitoring_active = getattr(config, 'monitoring_active', True)
                    pii_patterns = getattr(config, 'pii_patterns', True)
                    spii_patterns = getattr(config, 'spii_patterns', True)
                
                # Skip if monitoring is inactive for this user
                if not monitoring_active:
                    logger.info(f"Network monitoring is deactivated for user {user.id}. Skipping analysis.")
                    continue
                    
                # Get active keywords for this user
                try:
                    active_keywords = Keyword.query.filter_by(user_id=user.id, active=True).all()
                    if active_keywords:
                        keyword_list = [(k.keyword, k.id, k.priority) for k in active_keywords]
                        # Set in analyzer if method exists
                        if hasattr(analyzer, 'set_keywords'):
                            analyzer.set_keywords(keyword_list)
                except Exception as e:
                    logger.error(f"Error loading keywords for user {user.id}: {str(e)}")
                    keyword_list = []
                
                # Set custom alert rules if available
                if config and hasattr(config, 'custom_rules') and hasattr(analyzer, 'set_custom_rules'):
                    try:
                        custom_rules = config.get_custom_rules()
                        if custom_rules:
                            analyzer.set_custom_rules(custom_rules)
                            logger.info(f"Loaded {len(custom_rules)} custom rules for user {user.id}")
                    except Exception as e:
                        logger.error(f"Error loading custom rules for user {user.id}: {str(e)}")
                
                # Capture and analyze packets
                traffic_data = analyzer.capture_packets(duration=10, ports=monitored_ports, config=config, user_id=user.id)
                if traffic_data:
                    # Save traffic stats
                    timestamp = datetime.now()
                    for port, count in traffic_data.get('port_counts', {}).items():
                        stats = NetworkStats(
                            user_id=user.id,
                            timestamp=timestamp,
                            port=port,
                            packet_count=count,
                            bytes_transferred=traffic_data.get('port_bytes', {}).get(port, 0)
                        )
                        db.session.add(stats)
                    
                    # Save packet logs
                    for packet in traffic_data.get('packet_logs', []):
                        packet_log = PacketLog(
                            user_id=user.id,
                            timestamp=packet.get('timestamp', timestamp),
                            source_ip=packet.get('source_ip', ''),
                            destination_ip=packet.get('destination_ip', ''),
                            source_port=packet.get('source_port', 0),
                            destination_port=packet.get('destination_port', 0),
                            protocol=packet.get('protocol', ''),
                            length=packet.get('length', 0),
                            flags=packet.get('flags', ''),
                            description=packet.get('description', '')
                        )
                        db.session.add(packet_log)
                    
                    # Process PII detections
                    if pii_patterns:
                        for detection in traffic_data.get('pii_detections', []):
                            alert = Alert(
                                user_id=user.id,
                                timestamp=timestamp,
                                alert_type="PII_LEAK",
                                severity="HIGH",
                                message=f"PII detected: {detection.get('type', 'unknown')}",
                                source_ip=detection.get('src_ip', ''),
                                destination_ip=detection.get('dst_ip', ''),
                                port=detection.get('src_port', 0),
                                protocol=detection.get('protocol', ''),
                                payload_excerpt=detection.get('excerpt', '')
                            )
                            db.session.add(alert)
                            db.session.flush()  # Get the alert ID
                            process_notifications(alert)
                    
                    # Process SPII detections
                    if spii_patterns:
                        for detection in traffic_data.get('spii_detections', []):
                            alert = Alert(
                                user_id=user.id,
                                timestamp=timestamp,
                                alert_type="SPII_LEAK",
                                severity="CRITICAL",
                                message=f"SPII detected: {detection.get('type', 'unknown')}",
                                source_ip=detection.get('src_ip', ''),
                                destination_ip=detection.get('dst_ip', ''),
                                port=detection.get('src_port', 0),
                                protocol=detection.get('protocol', ''),
                                payload_excerpt=detection.get('excerpt', '')
                            )
                            db.session.add(alert)
                            db.session.flush()  # Get the alert ID
                            process_notifications(alert)
                    
                    # Process keyword matches
                    for match in traffic_data.get('keyword_matches', []):
                        # Only if keyword belongs to this user
                        keyword_id = match.get('keyword_id')
                        if keyword_id:
                            keyword = Keyword.query.get(keyword_id)
                            if keyword and keyword.user_id == user.id:
                                alert = Alert(
                                    user_id=user.id,
                                    timestamp=timestamp,
                                    alert_type="KEYWORD_MATCH",
                                    severity=match.get('priority', 'MEDIUM'),
                                    message=f"Keyword match: {match.get('keyword', 'unknown')}",
                                    source_ip=match.get('src_ip', ''),
                                    destination_ip=match.get('dst_ip', ''),
                                    port=match.get('src_port', 0),
                                    protocol=match.get('protocol', ''),
                                    payload_excerpt=match.get('excerpt', ''),
                                    keyword_id=keyword_id
                                )
                                db.session.add(alert)
                                db.session.flush()  # Get the alert ID
                                process_notifications(alert)
                    
                    # Process custom rule matches
                    custom_rule_matches = traffic_data.get('custom_rule_matches', [])
                    for rule_match in custom_rule_matches:
                        rule_type = rule_match.get('type', 'CUSTOM_RULE_MATCH')
                        severity = rule_match.get('severity', 'MEDIUM')
                        port = rule_match.get('port', 0)
                        rule_name = rule_match.get('rule_name', 'Custom Rule')
                        
                        # Construct appropriate message based on rule type
                        if rule_type == 'THRESHOLD_EXCEEDED':
                            message = f"Threshold exceeded on port {port}: {rule_match.get('current_value', 0)} {rule_match.get('metric', 'packets')} (threshold: {rule_match.get('threshold', 0)})"
                        elif rule_type == 'PORT_SCAN':
                            source_ip = rule_match.get('source_ip', '')
                            message = f"Potential port scan detected from {source_ip} ({rule_match.get('ports_scanned', 0)} ports in {rule_match.get('time_window', 60)} seconds)"
                            port = 0  # Port scan doesn't have a specific port
                        elif rule_type == 'BANDWIDTH_EXCEEDED':
                            message = f"Bandwidth threshold exceeded on port {port}: {rule_match.get('current_value', 0)} bytes (threshold: {rule_match.get('threshold', 0)} bytes)"
                        else:
                            message = f"Custom rule '{rule_name}' triggered"
                        
                        alert = Alert(
                            user_id=user.id,
                            timestamp=timestamp,
                            alert_type=f"CUSTOM_RULE_{rule_type}",
                            severity=severity,
                            message=message,
                            source_ip=rule_match.get('source_ip', ''),
                            destination_ip=rule_match.get('destination_ip', ''),
                            port=port,
                            protocol=rule_match.get('protocol', '')
                        )
                        db.session.add(alert)
                        db.session.flush()  # Get the alert ID
                        process_notifications(alert)
                    
                    # Check for anomalies
                    anomalies = detector.detect_anomalies(traffic_data)
                    for anomaly in anomalies:
                        alert = Alert(
                            user_id=user.id,
                            timestamp=timestamp,
                            alert_type=anomaly.get('type', 'TRAFFIC_ANOMALY'),
                            severity=anomaly.get('severity', 'MEDIUM'),
                            message=anomaly.get('message', 'Unusual network activity detected'),
                            source_ip=anomaly.get('source_ip', ''),
                            destination_ip=anomaly.get('destination_ip', ''),
                            port=anomaly.get('port', 0),
                            protocol=anomaly.get('protocol', '')
                        )
                        db.session.add(alert)
                        db.session.flush()  # Get the alert ID
                        process_notifications(alert)
                    
                    db.session.commit()
                    logger.info(f"Completed network analysis cycle for user {user.id}. Found {len(anomalies)} anomalies and {len(custom_rule_matches)} custom rule matches.")
                else:
                    logger.warning(f"No traffic data collected for user {user.id} in this cycle.")
        except Exception as e:
            logger.error(f"Error in network analysis task: {str(e)}")
            db.session.rollback()

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = TelField('Phone Number (for SMS-style alerts via ntfy.sh)', validators=[Length(max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    email_alerts = BooleanField('Receive Email Alerts', default=True)
    sms_alerts = BooleanField('Receive SMS-style Alerts via ntfy.sh', default=False)
    ntfy_alerts = BooleanField('Receive ntfy.sh Alerts', default=True)
    submit = SubmitField('Register')
    
class KeywordForm(FlaskForm):
    keyword = StringField('Keyword', validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Optional(), Length(max=255)])
    priority = SelectField('Priority', choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High')], default='MEDIUM')
    submit = SubmitField('Add Keyword')

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/emergency-access', methods=['GET', 'POST'])
def emergency_access():
    """Emergency access route to unlock accounts or bypass account lockout"""
    if request.method == 'POST':
        email = request.form.get('email')
        reset_code = request.form.get('reset_code')
        
        # Simple emergency reset code - in a real application, this would be more secure
        emergency_reset_code = "RAAPD-RESET-2025"
        
        if not email or not reset_code:
            flash('Please provide both email and reset code.', 'warning')
            return render_template('emergency_access.html')
            
        if reset_code != emergency_reset_code:
            flash('Invalid reset code. Please try again or contact support.', 'danger')
            return render_template('emergency_access.html')
            
        # Find user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No user found with that email address.', 'danger')
            return render_template('emergency_access.html')
            
        # Reset account lockout
        user.failed_login_attempts = 0
        user.locked_until = None
        user.lockout_notification_sent = False
        db.session.commit()
        
        flash('Your account has been successfully unlocked. You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('emergency_access.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Find user by email
        user = User.query.filter_by(email=form.email.data).first()
        
        # If user not found, show general error
        if not user:
            flash('Login failed. Please check your email and password.', 'danger')
            return render_template('login.html', form=form, active_page='login')
        
        # First check if lockout period has expired
        if user.locked_until and user.locked_until <= datetime.utcnow():
            # Reset lockout flags
            user.failed_login_attempts = 0
            user.lockout_notification_sent = False
            user.locked_until = None
            db.session.commit()
            flash('Your account lockout period has expired. You can now log in.', 'info')
        
        # Check if account is still locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            minutes_left = max(1, int((user.locked_until - datetime.utcnow()).total_seconds() / 60))
            flash(f'Account is locked. Please try again in {minutes_left} minutes.', 'danger')
            return render_template('login.html', form=form, active_page='login')
        
        # At this point, account is not locked - check password
        if user.check_password(form.password.data):
            # Reset login attempts and update last login time
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log the user in
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            
            # Redirect to the requested page or dashboard
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            # Invalid password - increment failed attempts
            user.failed_login_attempts += 1
            
            # Lock account after 3 failed attempts
            if user.failed_login_attempts >= 3:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                flash('Account locked for 30 minutes due to multiple failed login attempts.', 'danger')
                
                # Mark notifications as sent immediately to avoid retries
                user.lockout_notification_sent = True
                
                # Save the changes so far to ensure the lockout status is recorded
                db.session.commit()
                
                # Only attempt to send notifications if necessary
                # We do this after committing the lockout state to ensure the page doesn't hang
                lockout_message = "Login attempt failed. Your account has been locked for 30 minutes."
                
                try:
                    # Parse user's preferred ntfy servers if available
                    preferred_servers = None
                    if hasattr(user, 'ntfy_servers') and user.ntfy_servers:
                        try:
                            import json
                            preferred_servers = json.loads(user.ntfy_servers)
                            if preferred_servers and isinstance(preferred_servers, list):
                                logger.info(f"Using {len(preferred_servers)} preferred ntfy servers for lockout notification to user {user.id}")
                        except Exception as e:
                            logger.error(f"Failed to parse ntfy_servers for user {user.id}: {str(e)}")
                    
                    # SMS alerts are now handled through ntfy.sh (Twilio removed)
                    if user.sms_alerts and user.phone:
                        send_sms(user.phone, lockout_message, preferred_servers=preferred_servers)
                        logger.info(f"SMS-style lockout alert sent via ntfy.sh for {user.phone}")
                    
                    # Send direct ntfy notification if enabled
                    if user.ntfy_alerts and user.ntfy_topic:
                        send_ntfy_notification(
                            topic=user.ntfy_topic,
                            title="RAAPD Security Alert",
                            message=lockout_message,
                            priority="high",
                            tags=["warning", "lock"],
                            preferred_servers=preferred_servers
                        )
                        logger.info(f"ntfy.sh lockout alert sent to topic {user.ntfy_topic}")
                except Exception as e:
                    # Just log any errors and continue - don't let notification issues block login
                    logger.error(f"Error sending lockout notification: {str(e)}")
            else:
                # Not enough failed attempts to lock yet
                remaining = 3 - user.failed_login_attempts
                flash(f'Invalid password. {remaining} {"attempts" if remaining > 1 else "attempt"} remaining before account lockout.', 'warning')
            
            # Save changes
            db.session.commit()
    
    return render_template('login.html', form=form, active_page='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # If user is already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            email_alerts=form.email_alerts.data,
            sms_alerts=form.sms_alerts.data,
            ntfy_alerts=form.ntfy_alerts.data,
            ntfy_topic=f"raapd-{hash(form.username.data) % 10000000:07d}"  # Generate a unique topic based on username
        )
        user.set_password(form.password.data)
        
        # Save to database
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', form=form, active_page='register')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html', active_page='alerts')

@app.route('/architecture')
@login_required
def architecture():
    return render_template('architecture.html', active_page='architecture')

@app.route('/diagrams')
@login_required
def diagrams():
    return render_template('diagrams.html', active_page='diagrams')

@app.route('/config', methods=['GET', 'POST'])
@login_required
def config():
    # Get user-specific configuration
    config_data = Config.query.filter_by(user_id=current_user.id).first()
    if not config_data:
        # Create a new configuration for this user
        config_data = Config(
            user_id=current_user.id,
            monitored_ports="80,443,8080",
            pii_patterns=True,
            spii_patterns=True,
            alert_threshold=0.7,
            monitoring_active=True
        )
        db.session.add(config_data)
        db.session.commit()
    
    # Handle keyword submission
    keyword_form = KeywordForm()
    if keyword_form.validate_on_submit():
        # Create new keyword
        keyword = Keyword(
            user_id=current_user.id,
            keyword=keyword_form.keyword.data,
            description=keyword_form.description.data,
            priority=keyword_form.priority.data
        )
        db.session.add(keyword)
        db.session.commit()
        flash('Keyword added successfully!', 'success')
        return redirect(url_for('config'))
    
    # Get user's keywords
    keywords = Keyword.query.filter_by(user_id=current_user.id).all()
    
    return render_template('config.html', active_page='config', config=config_data, 
                          form=keyword_form, keywords=keywords)

# API routes
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    # If this is an AJAX request, handle authentication separately
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'error': 'Authentication required',
                'alerts': [],
                'count': 0
            }), 401
        else:
            return redirect(url_for('login', next=request.url))
    
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    # Get severity and type filter parameters
    severity = request.args.get('severity')
    alert_type = request.args.get('type')
    reviewed = request.args.get('reviewed')
    since = request.args.get('since')
    
    try:
        # Base query - filter by the current user
        query = Alert.query.filter_by(user_id=current_user.id)
        
        # Filter by timestamp if provided
        if since:
            try:
                since_datetime = datetime.fromisoformat(since.replace('Z', '+00:00'))
                query = query.filter(Alert.timestamp >= since_datetime)
            except (ValueError, TypeError):
                # If timestamp parsing fails, ignore the filter
                pass
        
        # Apply filters if provided
        if severity:
            query = query.filter(Alert.severity == severity)
        if alert_type:
            query = query.filter(Alert.alert_type == alert_type)
        if reviewed is not None:
            if reviewed.lower() == 'true':
                query = query.filter(Alert.reviewed == True)
            elif reviewed.lower() == 'false':
                query = query.filter(Alert.reviewed == False)
        
        # Get filtered alerts, sorted by timestamp (newest first)
        alerts = query.order_by(Alert.timestamp.desc()).limit(limit).offset(offset).all()
        
        return jsonify({
            'count': query.count(),
            'alerts': [alert.to_dict() for alert in alerts]
        })
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        return jsonify({
            'error': f"Error getting alerts: {str(e)}",
            'alerts': [],
            'count': 0
        }), 500

@app.route('/api/alerts/<int:alert_id>/mark-reviewed', methods=['POST'])
def mark_alert_as_reviewed(alert_id):
    """Mark an alert as reviewed."""
    # If this is an AJAX request, handle authentication separately
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Authentication required'}), 401
        else:
            return redirect(url_for('login', next=request.url))
    
    # Find the alert
    alert = Alert.query.filter_by(id=alert_id, user_id=current_user.id).first()
    
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    # Update the alert
    try:
        alert.reviewed = True
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alert marked as reviewed'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error marking alert as reviewed: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    # If this is an AJAX request, handle authentication separately
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'error': 'Authentication required'
            }), 401
        else:
            return redirect(url_for('login', next=request.url))
    
    # Get timeframe parameter  
    timeframe = request.args.get('timeframe', '1h')
    
    try:
        # Base query - filter by the current user
        base_query = NetworkStats.query.filter_by(user_id=current_user.id)
        
        # Get stats based on timeframe
        if timeframe == '1h':
            # Last hour stats
            since = datetime.now().replace(minute=0, second=0, microsecond=0)
            stats = base_query.filter(NetworkStats.timestamp >= since).all()
        elif timeframe == '24h':
            # Last 24 hours stats
            since = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            stats = base_query.filter(NetworkStats.timestamp >= since).all()
        else:
            # Default to all stats
            stats = base_query.all()
        
        # Aggregate data by port
        aggregated_stats = {}
        for stat in stats:
            if stat.port not in aggregated_stats:
                aggregated_stats[stat.port] = {
                    'packet_count': 0,
                    'bytes_transferred': 0,
                    'timestamps': []
                }
            aggregated_stats[stat.port]['packet_count'] += stat.packet_count
            aggregated_stats[stat.port]['bytes_transferred'] += stat.bytes_transferred
            aggregated_stats[stat.port]['timestamps'].append(stat.timestamp.isoformat())
        
        return jsonify(aggregated_stats)
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'error': f"Error getting stats: {str(e)}"}), 500

@app.route('/api/packets', methods=['GET'])
def get_packets():
    limit = request.args.get('limit', 10, type=int)
    offset = request.args.get('offset', 0, type=int)
    since = request.args.get('since')
    
    # If this is an AJAX request, handle authentication separately
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'error': 'Authentication required',
                'packets': [],
                'count': 0
            }), 401
        else:
            return redirect(url_for('login', next=request.url))
    
    # Build query filter
    query = PacketLog.query.filter_by(user_id=current_user.id)
    
    # Filter by timestamp if provided
    if since:
        try:
            since_datetime = datetime.fromisoformat(since.replace('Z', '+00:00'))
            query = query.filter(PacketLog.timestamp >= since_datetime)
        except (ValueError, TypeError):
            # If timestamp parsing fails, ignore the filter
            pass
    
    # Get packets with filters applied
    user_packets = query.order_by(PacketLog.timestamp.desc()).limit(limit).offset(offset).all()
    
    # Count also respects the time filter if provided
    count_query = PacketLog.query.filter_by(user_id=current_user.id)
    if since:
        try:
            since_datetime = datetime.fromisoformat(since.replace('Z', '+00:00'))
            count_query = count_query.filter(PacketLog.timestamp >= since_datetime)
        except (ValueError, TypeError):
            pass
    
    return jsonify({
        'count': count_query.count(),
        'packets': [packet.to_dict() for packet in user_packets]
    })

@app.route('/api/keywords/<int:keyword_id>/delete', methods=['POST'])
def delete_keyword(keyword_id):
    # If this is an AJAX request, handle authentication separately
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'error': 'Authentication required',
                'success': False
            }), 401
        else:
            return redirect(url_for('login', next=request.url))
    
    try:
        keyword = Keyword.query.get_or_404(keyword_id)
        
        # Make sure the user owns this keyword
        if keyword.user_id != current_user.id:
            flash('You do not have permission to delete this keyword.', 'danger')
            return redirect(url_for('config'))
        
        # Delete the keyword
        db.session.delete(keyword)
        db.session.commit()
        
        flash('Keyword deleted successfully!', 'success')
        return redirect(url_for('config'))
    except Exception as e:
        logger.error(f"Error deleting keyword: {str(e)}")
        flash('Error deleting keyword.', 'danger')
        return redirect(url_for('config'))

@app.route('/api/keywords/<int:keyword_id>/toggle', methods=['POST'])
def toggle_keyword(keyword_id):
    # If this is an AJAX request, handle authentication separately
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'error': 'Authentication required',
                'success': False
            }), 401
        else:
            return redirect(url_for('login', next=request.url))
    
    try:
        keyword = Keyword.query.get_or_404(keyword_id)
        
        # Make sure the user owns this keyword
        if keyword.user_id != current_user.id:
            flash('You do not have permission to modify this keyword.', 'danger')
            return redirect(url_for('config'))
        
        # Toggle active status
        keyword.active = not keyword.active
        db.session.commit()
        
        status = "activated" if keyword.active else "deactivated"
        flash(f'Keyword "{keyword.keyword}" {status}!', 'success')
        return redirect(url_for('config'))
    except Exception as e:
        logger.error(f"Error toggling keyword: {str(e)}")
        flash('Error toggling keyword.', 'danger')
        return redirect(url_for('config'))

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    # If this is an AJAX request, handle authentication separately
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'error': 'Authentication required',
                'success': False
            }), 401
        else:
            return redirect(url_for('login', next=request.url))
    
    if request.method == 'GET':
        # Get the configuration for the current user
        config = Config.query.filter_by(user_id=current_user.id).first()
        if not config:
            # Create a default configuration for this user
            config = Config(
                user_id=current_user.id,
                monitored_ports="80,443,8080",
                pii_patterns=True,
                spii_patterns=True,
                alert_threshold=0.7,
                monitoring_active=False  # Default to inactive
            )
            db.session.add(config)
            db.session.commit()
            logger.info(f"Created default configuration for user {current_user.username}")
        return jsonify(config.to_dict())
    
    elif request.method == 'POST':
        try:
            data = request.json
            if data is None:
                logger.error("No JSON data received in request")
                return jsonify({'success': False, 'error': 'No data provided'}), 400
        except Exception as e:
            logger.error(f"Error parsing JSON data: {str(e)}")
            return jsonify({'success': False, 'error': 'Invalid JSON format'}), 400
        # Get or create the configuration for the current user
        config = Config.query.filter_by(user_id=current_user.id).first()
        if not config:
            config = Config(user_id=current_user.id)
        
        # Update basic configuration fields
        if 'monitored_ports' in data:
            config.monitored_ports = data['monitored_ports']
        if 'pii_patterns' in data:
            config.pii_patterns = data['pii_patterns']
        if 'spii_patterns' in data:
            config.spii_patterns = data['spii_patterns']
        if 'alert_threshold' in data:
            config.alert_threshold = data['alert_threshold']
        if 'monitoring_active' in data:
            config.monitoring_active = data['monitoring_active']
            logger.info(f"Network monitoring {'activated' if data['monitoring_active'] else 'deactivated'}")
        
        # Update custom alert rules fields
        if 'packet_threshold' in data:
            config.packet_threshold = data['packet_threshold']
        if 'bandwidth_threshold' in data:
            config.bandwidth_threshold = data['bandwidth_threshold']
        if 'alert_on_port_scan' in data:
            config.alert_on_port_scan = data['alert_on_port_scan']
        if 'port_scan_threshold' in data:
            config.port_scan_threshold = data['port_scan_threshold']
        if 'custom_rules' in data:
            # Validate custom rules JSON
            try:
                # If it's a string, try to parse it
                if isinstance(data['custom_rules'], str):
                    import json
                    json.loads(data['custom_rules'])
                # If it's already a dict/list, it will be serialized by to_dict()
                config.custom_rules = data['custom_rules']
                logger.info(f"Updated custom rules configuration for user {current_user.id}")
            except Exception as e:
                logger.error(f"Invalid custom rules format: {e}")
                return jsonify({
                    'success': False, 
                    'error': 'Invalid custom rules format'
                }), 400
                
        # Update SIEM integration configuration
        if 'siem_config' in data:
            try:
                import json
                
                # If it's a string, try to parse it before storing
                if isinstance(data['siem_config'], str):
                    siem_config = json.loads(data['siem_config'])
                else:
                    siem_config = data['siem_config']
                
                # Validate basic structure
                if not isinstance(siem_config, dict):
                    raise ValueError("SIEM config must be an object")
                
                # Set the configuration
                config.set_siem_config(siem_config)
                logger.info(f"Updated SIEM integration configuration for user {current_user.id}")
                
            except Exception as e:
                logger.error(f"Invalid SIEM configuration format: {e}")
                return jsonify({
                    'success': False, 
                    'error': 'Invalid SIEM configuration format'
                }), 400
        
        db.session.add(config)
        db.session.commit()
        return jsonify({'success': True, 'config': config.to_dict()})

# Initialize the database
with app.app_context():
    # Import models
    import models
    
    # Create tables
    db.create_all()
    
    try:
        # Check if we have a configuration entry
        if Config.query.count() == 0:
            # Find the first user or create a default user
            default_user = User.query.first()
            
            if default_user:
                default_config = Config(
                    user_id=default_user.id,
                    monitored_ports="80,443,8080",
                    pii_patterns=True,
                    spii_patterns=True,
                    alert_threshold=0.7,
                    monitoring_active=True
                )
                db.session.add(default_config)
                db.session.commit()
                logger.info(f"Created default configuration for user {default_user.username}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during database initialization: {str(e)}")

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=analyze_network_traffic, trigger="interval", seconds=1)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

@app.route('/api/user/preferences', methods=['POST'])
@login_required
def update_user_preferences():
    """Update user notification preferences."""
    if not request.is_json:
        return jsonify({'error': 'Invalid request format. JSON required.'}), 400
    
    data = request.get_json()
    response = {'success': False}
    
    # Global notifications switch (master switch)
    if 'notifications_enabled' in data:
        current_user.notifications_enabled = bool(data['notifications_enabled'])
        # Log the change for monitoring
        app.logger.info(f"User {current_user.username} set notifications master switch to: {current_user.notifications_enabled}")
        response['success'] = True
    
    # Email alert preference
    if 'email_alerts' in data:
        current_user.email_alerts = bool(data['email_alerts'])
        response['success'] = True
    
    # SMS alert preference
    if 'sms_alerts' in data:
        current_user.sms_alerts = bool(data['sms_alerts'])
        response['success'] = True
        
    # ntfy.sh alert preference
    if 'ntfy_alerts' in data:
        current_user.ntfy_alerts = bool(data['ntfy_alerts'])
        
        # Generate a unique ntfy.sh topic if needed and enabled
        if current_user.ntfy_alerts and not current_user.ntfy_topic:
            # Generate a unique topic based on user ID and a random component
            import random
            topic_id = random.randint(1000000, 9999999)
            current_user.ntfy_topic = f"raapd-{topic_id}"
            response['ntfy_topic'] = current_user.ntfy_topic
            
        response['success'] = True
    
    # Save changes if any preferences were updated
    if response['success']:
        db.session.commit()
        
    return jsonify(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
