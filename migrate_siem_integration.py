"""
Migration script to add SIEM integration tables to the database.

This script adds:
1. A SIEMConfig table to store SIEM export configurations
"""

import json
import logging
import os
import sqlalchemy
from sqlalchemy.exc import SQLAlchemyError, OperationalError

logger = logging.getLogger(__name__)

def execute_sql(sql, params=None):
    """Execute SQL directly with SQLAlchemy engine"""
    from app import db
    
    if params is None:
        params = {}
    
    try:
        with db.engine.connect() as conn:
            conn.execute(sqlalchemy.text(sql), params)
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        return False

def check_column_exists(table, column):
    """Check if column exists in table"""
    from app import db
    
    try:
        with db.engine.connect() as conn:
            result = conn.execute(sqlalchemy.text(
                f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_name = '{table}' AND column_name = '{column}'"
            ))
            exists = result.fetchone() is not None
            conn.commit()
        return exists
    except Exception as e:
        logger.error(f"Error checking column existence: {str(e)}")
        return False

def check_table_exists(table):
    """Check if table exists in database"""
    from app import db
    
    try:
        with db.engine.connect() as conn:
            result = conn.execute(sqlalchemy.text(
                f"SELECT table_name FROM information_schema.tables "
                f"WHERE table_name = '{table}'"
            ))
            exists = result.fetchone() is not None
            conn.commit()
        return exists
    except Exception as e:
        logger.error(f"Error checking table existence: {str(e)}")
        return False

def migrate():
    """Run database migrations for SIEM integration"""
    try:
        # Step 1: Add siem_config column to Config table if not exists
        if not check_column_exists('config', 'siem_config'):
            logger.info("Adding siem_config column to Config table")
            execute_sql("""
                ALTER TABLE config 
                ADD COLUMN siem_config TEXT DEFAULT '{"enabled": false, "methods": ["syslog"], "format": "cef"}'
            """)
            logger.info("Added siem_config column to Config table")
        else:
            logger.info("siem_config column already exists in Config table")
        
        # Step 2: Add SIEMExport table if not exists
        if not check_table_exists('siem_export'):
            logger.info("Creating SIEMExport table")
            execute_sql("""
                CREATE TABLE siem_export (
                    id SERIAL PRIMARY KEY,
                    alert_id INTEGER NOT NULL,
                    user_id INTEGER,
                    export_method VARCHAR(50) NOT NULL,
                    export_status VARCHAR(20) NOT NULL,
                    export_destination VARCHAR(255),
                    export_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    response_data TEXT,
                    FOREIGN KEY (alert_id) REFERENCES alert (id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE SET NULL
                )
            """)
            logger.info("Created SIEMExport table")
        else:
            logger.info("SIEMExport table already exists")
        
        # Step 3: Create SIEMConnection table if not exists
        if not check_table_exists('siem_connection'):
            logger.info("Creating SIEMConnection table")
            execute_sql("""
                CREATE TABLE siem_connection (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    connection_name VARCHAR(100) NOT NULL,
                    connection_type VARCHAR(50) NOT NULL,
                    connection_details TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE
                )
            """)
            logger.info("Created SIEMConnection table")
        else:
            logger.info("SIEMConnection table already exists")
        
        # Step 4: Create default SIEM integrations
        logger.info("Migration completed successfully")
        return True
    
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from app import app
    with app.app_context():
        success = migrate()
        if success:
            print("SIEM integration migration completed successfully")
        else:
            print("SIEM integration migration failed, check logs for details")