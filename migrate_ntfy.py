import logging
import os
import sqlalchemy
from sqlalchemy import create_engine, text

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database connection from environment variables
DATABASE_URL = os.environ.get("DATABASE_URL")

def execute_sql(sql, params=None):
    """Execute SQL directly with SQLAlchemy engine"""
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        conn.commit()
    return result

def check_column_exists(table, column):
    """Check if column exists in table"""
    try:
        sql = f"""
        SELECT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name='{table}' AND column_name='{column}'
        )
        """
        result = execute_sql(sql)
        return result.scalar()
    except Exception as e:
        logger.error(f"Error checking if column {column} exists in {table}: {str(e)}")
        return False

def migrate():
    """Run database migrations for ntfy.sh integration"""
    try:
        logger.info("Starting ntfy.sh integration migration")
        
        # Check and add ntfy_alerts column to User table
        if not check_column_exists('user', 'ntfy_alerts'):
            logger.info("Adding ntfy_alerts column to User table")
            execute_sql("""
                ALTER TABLE "user" 
                ADD COLUMN ntfy_alerts BOOLEAN DEFAULT TRUE
            """)
        
        # Check and add ntfy_topic column to User table
        if not check_column_exists('user', 'ntfy_topic'):
            logger.info("Adding ntfy_topic column to User table")
            execute_sql("""
                ALTER TABLE "user" 
                ADD COLUMN ntfy_topic VARCHAR(100)
            """)
        
        # Check and add ntfy_sent column to Alert table
        if not check_column_exists('alert', 'ntfy_sent'):
            logger.info("Adding ntfy_sent column to Alert table")
            execute_sql("""
                ALTER TABLE alert 
                ADD COLUMN ntfy_sent BOOLEAN DEFAULT FALSE
            """)
        
        # Generate ntfy_topic for all existing users based on username hash
        logger.info("Setting default ntfy topics for all users")
        execute_sql("""
            UPDATE "user"
            SET ntfy_topic = 'raapd-' || ABS(('x' || MD5(username))::bit(60)::bigint % 10000000)
            WHERE ntfy_topic IS NULL
        """)
        
        logger.info("Migration completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        return False

if __name__ == "__main__":
    migrate()