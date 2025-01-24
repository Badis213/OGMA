import sqlite3
import psycopg2

# Supabase credentials
SUPABASE_HOST = "db.xfcpapqljrzleudktcrc.supabase.co"
SUPABASE_DB_USER = "postgres"
SUPABASE_DB_PASSWORD = "Badis_J135"
SUPABASE_DB_NAME = "postgres"
SUPABASE_PORT = 5432

# SQLite database path
SQLITE_DB_PATH = "backup.db"

# Connect to SQLite database
def connect_sqlite(db_path):
    try:
        connection = sqlite3.connect(db_path)
        print("Connected to SQLite database.")
        return connection
    except sqlite3.Error as e:
        print(f"SQLite connection error: {e}")
        exit(1)

# Connect to Supabase PostgreSQL database
def connect_postgres(host, db_name, user, password, port):
    try:
        connection = psycopg2.connect(
            host=host,
            database=db_name,
            user=user,
            password=password,
            port=port,
            connect_timeout=10  # Optional: Set a connection timeout
        )
        connection.autocommit = True
        print("Connected to Supabase PostgreSQL database.")
        return connection
    except psycopg2.OperationalError as e:
        print(f"PostgreSQL connection error: {e}")
        exit(1)

# Transfer data from SQLite to PostgreSQL
def transfer_data(sqlite_conn, postgres_conn):
    try:
        sqlite_cursor = sqlite_conn.cursor()
        postgres_cursor = postgres_conn.cursor()

        # Fetch all table names from SQLite
        sqlite_cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table';"
        )
        tables = sqlite_cursor.fetchall()

        for table_name, in tables:
            print(f"Transferring table: {table_name}")
            
            # Escape table name if it's a reserved keyword
            escaped_table_name = f'"{table_name}"'

            # Fetch column names from SQLite
            sqlite_cursor.execute(f"PRAGMA table_info({table_name});")
            columns = [col[1] for col in sqlite_cursor.fetchall()]
            column_names = ", ".join(columns)

            # Fetch all rows from the table
            sqlite_cursor.execute(f"SELECT * FROM {table_name};")
            rows = sqlite_cursor.fetchall()

            # Create table in PostgreSQL
            create_table_query = f"""
            CREATE TABLE IF NOT EXISTS {escaped_table_name} (
                {', '.join([f'"{col}" TEXT' for col in columns])}
            );
            """
            postgres_cursor.execute(create_table_query)

            # Insert data into PostgreSQL
            insert_query = f"""
            INSERT INTO {escaped_table_name} ({', '.join([f'"{col}"' for col in columns])})
            VALUES ({', '.join(['%s'] * len(columns))})
            """
            for row in rows:
                postgres_cursor.execute(insert_query, row)

            print(f"Table {table_name} transferred successfully.")
    except Exception as e:
        print(f"Error during data transfer: {e}")
    finally:
        sqlite_cursor.close()
        postgres_cursor.close()

# Main execution
def main():
    # Connect to both databases
    sqlite_conn = connect_sqlite(SQLITE_DB_PATH)
    postgres_conn = connect_postgres(
        host=SUPABASE_HOST,
        db_name=SUPABASE_DB_NAME,
        user=SUPABASE_DB_USER,
        password=SUPABASE_DB_PASSWORD,
        port=SUPABASE_PORT,
    )

    # Transfer data
    transfer_data(sqlite_conn, postgres_conn)

    # Close connections
    sqlite_conn.close()
    postgres_conn.close()
    print("Data transfer complete.")

if __name__ == "__main__":
    main()
