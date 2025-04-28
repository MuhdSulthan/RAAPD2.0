import os
import sys
import logging
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get database URL from environment variable
DATABASE_URL = os.environ.get('DATABASE_URL')

if not DATABASE_URL:
    logger.error("DATABASE_URL environment variable not set")
    sys.exit(1)

def execute_sql(sql, params=None):
    """Execute SQL directly with SQLAlchemy engine"""
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        if params:
            result = conn.execute(text(sql), params)
        else:
            result = conn.execute(text(sql))
        conn.commit()
        return result

def check_table_exists(table):
    """Check if table exists in database"""
    engine = create_engine(DATABASE_URL)
    inspector = inspect(engine)
    return table in inspector.get_table_names()

def migrate():
    """Run database migrations for pattern definitions"""
    try:
        # Check if PatternDefinition table already exists
        if check_table_exists('pattern_definition'):
            logger.info("PatternDefinition table already exists, skipping migration")
            return
        
        # Create the table
        logger.info("Creating PatternDefinition table...")
        execute_sql("""
            CREATE TABLE pattern_definition (
                id SERIAL PRIMARY KEY,
                pattern_name VARCHAR(100) NOT NULL,
                pattern_regex VARCHAR(500) NOT NULL,
                pattern_type VARCHAR(20) NOT NULL,
                description VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE,
                is_default BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER REFERENCES "user" (id)
            );
        """)
        
        # Add default patterns for PII
        logger.info("Adding default PII patterns...")
        execute_sql("""
            INSERT INTO pattern_definition 
            (pattern_name, pattern_regex, pattern_type, description, is_active, is_default) 
            VALUES 
            ('Email', E'\\\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Z|a-z]{2,}\\\\b', 'PII', 'Email address pattern', TRUE, TRUE),
            ('SSN', E'\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b', 'PII', 'Social Security Number', TRUE, TRUE),
            ('Credit Card', E'\\\\b(?:\\\\d{4}[-\\\\s]?){3}\\\\d{4}\\\\b', 'PII', 'Credit card number', TRUE, TRUE),
            ('Phone Number', E'\\\\b\\\\(?\\\\d{3}\\\\)?[-.\\\\ s]?\\\\d{3}[-.\\\\ s]?\\\\d{4}\\\\b', 'PII', 'Phone number', TRUE, TRUE),
            ('Address', E'\\\\b\\\\d+\\\\ s+[A-Za-z\\\\s]+\\\\ s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\\\\b', 'PII', 'Street address', TRUE, TRUE),
            ('IP Address', E'\\\\b(?:\\\\d{1,3}\\\\.){3}\\\\d{1,3}\\\\b', 'PII', 'IP address', TRUE, TRUE);
        """)
        
        # Add default patterns for SPII
        logger.info("Adding default SPII patterns...")
        execute_sql("""
            INSERT INTO pattern_definition 
            (pattern_name, pattern_regex, pattern_type, description, is_active, is_default) 
            VALUES 
            ('Passport', E'\\\\b[A-Za-z]\\\\d{8}\\\\b', 'SPII', 'Passport number', TRUE, TRUE),
            ('Date of Birth', E'\\\\b\\\\d{1,2}[-/]\\\\d{1,2}[-/]\\\\d{2,4}\\\\b', 'SPII', 'Date of birth', TRUE, TRUE),
            ('Medical Record', E'\\\\b(?:MRN|Medical Record Number):\\\\s*\\\\w+\\\\b', 'SPII', 'Medical record number', TRUE, TRUE),
            ('Driver License', E'\\\\b[A-Za-z]\\\\d{7}\\\\b', 'SPII', 'Driver license number', TRUE, TRUE);
        """)
        
        logger.info("Migration completed successfully")
    except SQLAlchemyError as e:
        logger.error(f"Migration failed: {str(e)}")
        raise

if __name__ == "__main__":
    migrate()