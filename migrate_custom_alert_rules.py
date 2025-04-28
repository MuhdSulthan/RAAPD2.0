import os
import logging
import psycopg2
from psycopg2 import sql

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def execute_sql(query, params=None):
    """Execute SQL query with parameters"""
    conn = None
    try:
        # Get database URL from environment
        db_url = os.environ.get('DATABASE_URL')
        if not db_url:
            logger.error("DATABASE_URL environment variable not set")
            return False
        
        # Connect to the database
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        
        # Execute the query
        if params:
            cur.execute(query, params)
        else:
            cur.execute(query)
            
        # Commit the transaction
        conn.commit()
        
        # Return the cursor for potential results
        return cur
        
    except Exception as e:
        logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        return False
        
    finally:
        if conn:
            conn.close()

def check_column_exists(table, column):
    """Check if column exists in table"""
    query = """
    SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
    );
    """
    
    try:
        cur = execute_sql(query, (table, column))
        if cur:
            result = cur.fetchone()[0]
            return result
        return False
    except Exception as e:
        logger.error(f"Error checking if column exists: {e}")
        return False

def migrate():
    """Run migration to add custom alert rules columns"""
    logger.info("Starting migration for custom alert rules...")
    
    # Check if custom_rules column already exists
    if check_column_exists('config', 'custom_rules'):
        logger.info("Column custom_rules already exists. Skipping.")
    else:
        # Add custom_rules column
        query = """
        ALTER TABLE config
        ADD COLUMN custom_rules TEXT DEFAULT '[]';
        """
        if execute_sql(query):
            logger.info("Added custom_rules column to config table")
        else:
            logger.error("Failed to add custom_rules column")
            return False
    
    # Check and add packet_threshold column
    if check_column_exists('config', 'packet_threshold'):
        logger.info("Column packet_threshold already exists. Skipping.")
    else:
        query = """
        ALTER TABLE config
        ADD COLUMN packet_threshold INTEGER DEFAULT 1000;
        """
        if execute_sql(query):
            logger.info("Added packet_threshold column to config table")
        else:
            logger.error("Failed to add packet_threshold column")
            return False
    
    # Check and add bandwidth_threshold column
    if check_column_exists('config', 'bandwidth_threshold'):
        logger.info("Column bandwidth_threshold already exists. Skipping.")
    else:
        query = """
        ALTER TABLE config
        ADD COLUMN bandwidth_threshold INTEGER DEFAULT 1000000;
        """
        if execute_sql(query):
            logger.info("Added bandwidth_threshold column to config table")
        else:
            logger.error("Failed to add bandwidth_threshold column")
            return False
    
    # Check and add alert_on_port_scan column
    if check_column_exists('config', 'alert_on_port_scan'):
        logger.info("Column alert_on_port_scan already exists. Skipping.")
    else:
        query = """
        ALTER TABLE config
        ADD COLUMN alert_on_port_scan BOOLEAN DEFAULT TRUE;
        """
        if execute_sql(query):
            logger.info("Added alert_on_port_scan column to config table")
        else:
            logger.error("Failed to add alert_on_port_scan column")
            return False
    
    # Check and add port_scan_threshold column
    if check_column_exists('config', 'port_scan_threshold'):
        logger.info("Column port_scan_threshold already exists. Skipping.")
    else:
        query = """
        ALTER TABLE config
        ADD COLUMN port_scan_threshold INTEGER DEFAULT 5;
        """
        if execute_sql(query):
            logger.info("Added port_scan_threshold column to config table")
        else:
            logger.error("Failed to add port_scan_threshold column")
            return False
    
    logger.info("Migration for custom alert rules completed successfully")
    return True

if __name__ == "__main__":
    migrate()