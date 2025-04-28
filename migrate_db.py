import os
import sys
import logging
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError, ProgrammingError

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create a minimal Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///raapd.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

def execute_sql(sql, params=None):
    try:
        with db.engine.connect() as conn:
            if params:
                conn.execute(text(sql), params)
            else:
                conn.execute(text(sql))
            conn.commit()
        return True
    except SQLAlchemyError as e:
        logger.error(f"SQL Error: {str(e)}")
        return False

def check_column_exists(table, column):
    try:
        with db.engine.connect() as conn:
            # PostgreSQL specific query to check if column exists
            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :table AND column_name = :column"
            ), {"table": table, "column": column})
            return result.rowcount > 0
    except SQLAlchemyError as e:
        logger.error(f"Error checking column: {str(e)}")
        return False

def migrate():
    try:
        with app.app_context():
            # Check and update Config table
            if not check_column_exists("config", "monitoring_active"):
                logger.info("Adding monitoring_active column to Config table")
                execute_sql("ALTER TABLE config ADD COLUMN monitoring_active BOOLEAN DEFAULT TRUE")
            
            # Check and create User table if it doesn't exist
            execute_sql("""
                CREATE TABLE IF NOT EXISTS "user" (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL UNIQUE,
                    email VARCHAR(120) NOT NULL UNIQUE,
                    password_hash VARCHAR(256) NOT NULL,
                    phone VARCHAR(20),
                    is_active BOOLEAN DEFAULT TRUE,
                    is_admin BOOLEAN DEFAULT FALSE,
                    last_login TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    email_alerts BOOLEAN DEFAULT TRUE,
                    sms_alerts BOOLEAN DEFAULT FALSE,
                    alert_on_pii BOOLEAN DEFAULT TRUE,
                    alert_on_spii BOOLEAN DEFAULT TRUE,
                    alert_on_anomaly BOOLEAN DEFAULT TRUE,
                    alert_on_keywords BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Check and create Keyword table if it doesn't exist
            execute_sql("""
                CREATE TABLE IF NOT EXISTS keyword (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES "user"(id),
                    keyword VARCHAR(100) NOT NULL,
                    description VARCHAR(255),
                    priority VARCHAR(20) DEFAULT 'MEDIUM',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Update Alert table with new columns
            if not check_column_exists("alert", "protocol"):
                logger.info("Adding protocol column to Alert table")
                execute_sql("ALTER TABLE alert ADD COLUMN protocol VARCHAR(20)")
            
            if not check_column_exists("alert", "payload_excerpt"):
                logger.info("Adding payload_excerpt column to Alert table")
                execute_sql("ALTER TABLE alert ADD COLUMN payload_excerpt TEXT")
            
            if not check_column_exists("alert", "user_id"):
                logger.info("Adding user_id column to Alert table")
                execute_sql("ALTER TABLE alert ADD COLUMN user_id INTEGER REFERENCES \"user\"(id)")
            
            if not check_column_exists("alert", "keyword_id"):
                logger.info("Adding keyword_id column to Alert table")
                execute_sql("ALTER TABLE alert ADD COLUMN keyword_id INTEGER REFERENCES keyword(id)")
            
            if not check_column_exists("alert", "email_sent"):
                logger.info("Adding email_sent column to Alert table")
                execute_sql("ALTER TABLE alert ADD COLUMN email_sent BOOLEAN DEFAULT FALSE")
            
            if not check_column_exists("alert", "sms_sent"):
                logger.info("Adding sms_sent column to Alert table")
                execute_sql("ALTER TABLE alert ADD COLUMN sms_sent BOOLEAN DEFAULT FALSE")
            
            # Create PacketLog table
            execute_sql("""
                CREATE TABLE IF NOT EXISTS packet_log (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip VARCHAR(50),
                    destination_ip VARCHAR(50),
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol VARCHAR(20),
                    length INTEGER,
                    flags VARCHAR(50),
                    description TEXT
                )
            """)
            
            logger.info("Database migration completed successfully")
            return True
    except Exception as e:
        logger.error(f"Migration error: {str(e)}")
        return False

if __name__ == "__main__":
    success = migrate()
    sys.exit(0 if success else 1)