import psycopg2
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("Starting testapp")
    
    # Connection parameters
    conn_params = {
        'host': 'postgres',
        'user': 'postgres',
        'password': 'postgres',
        'dbname': 'postgres'
    }
    
    # Wait for Postgres to be ready
    while True:
        try:
            conn = psycopg2.connect(**conn_params)
            break
        except psycopg2.OperationalError as e:
            logger.info(f"waiting for postgres: {e}")
            time.sleep(1)
    
    logger.info("connected to postgres")
    
    try:
        # Create cursor
        cursor = conn.cursor()
        
        # Ensure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id   SERIAL PRIMARY KEY,
                name TEXT
            )
        """)
        conn.commit()
        
        # Insert a sample row
        try:
            cursor.execute("INSERT INTO users(name) VALUES(%s)", ("alice",))
            conn.commit()
        except Exception as e:
            logger.info(f"insert user: {e}")
            conn.rollback()
        
        # Infinite loop to query users
        while True:
            # This SELECT * should trigger PQexec inside libpq
            cursor.execute("SELECT * FROM users")
            rows = cursor.fetchall()
            
            logger.info("rows from users table:")
            for row in rows:
                user_id, name = row
                print(f"user: id={user_id} name={name}")
            
            # Keep the process alive for a bit so the agent can see activity
            logger.info("sleeping for 5s so the agent can profile libpq...")
            time.sleep(5)
            
    except Exception as e:
        logger.error(f"error: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()

