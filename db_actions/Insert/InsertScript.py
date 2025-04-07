import mysql.connector
from mysql.connector import errorcode
import os


def connect_db():
    """Establish a connection to the MySQL database."""
    try:
        cnx = mysql.connector.connect(
            host='localhost',  # Update with your host
            user='your_username',  # Update with your username
            password=os.environ.get('MYSQL_PASSWORD'),  # Update with your password
            database='your_database'  # Update with your database name
        )
        print("Connection successful.")
        return cnx
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Error: Check your username or password.")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Error: Database does not exist.")
        else:
            print(err)
        return None


def insert_data(cnx, table, data):
    """
    Inserts data into the specified table.

    Parameters:
        cnx (MySQLConnection): The database connection object.
        table (str): The name of the table.
        data (list of tuples): List of tuples where each tuple represents a row.
    """
    cursor = cnx.cursor()

    # Automatically generate the placeholder string based on the number of columns in the first row.
    placeholders = ", ".join(["%s"] * len(data[0]))
    sql = f"INSERT INTO {table} VALUES ({placeholders})"

    try:
        cursor.executemany(sql, data)
        cnx.commit()
        print(f"{cursor.rowcount} records inserted successfully.")
    except mysql.connector.Error as err:
        print("Failed inserting data: {}".format(err))
        cnx.rollback()
    finally:
        cursor.close()


def main():
    connection = connect_db()
    if connection is None:
        return
    tier_data = [
        ## give me fake data
    ]

    insert_data(connection, 'TIER', tier_data )

    user_data = [
        ## give me fake data
    ]
    insert_data(connection, 'USER', user_data )

    sales_data = [
        ## give me fake data
    ]

    insert_data(connection, 'SALES_TRANSACTION', sales_data )

    machine_data = [
        ## give me fake data
    ]

    insert_data(connection, 'MACHINE', machine_data)

    tasks_data = [
        ## give me fake data
    ]

    insert_data(connection, 'Tasks', tasks_data )

    executes_data = [
        ## give me fake data
    ]

    insert_data(connection, 'Executes', executes_data )
    connection.close()


if __name__ == "__main__":
    main()
