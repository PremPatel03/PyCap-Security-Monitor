import sqlite3
import pandas as pd

def generate_security_report():
    print(" IDS FORENSIC SUMMARY REPORT")
    
    try:
        # Connect to the existing DB created by the IDS
        conn = sqlite3.connect('network_alerts.db')
        
        # Total Alerts Count
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]
        print(f"Total Alerts Logged: {total_alerts}\n")
        
        if total_alerts == 0:
            print("No alerts found in the database. Run the IDS and generate traffic first.")
            return

        # Top Offending IP Addresses
        print("--- Top 5 Offending Source IPs ---")
        top_ips_query = """
            SELECT src_ip, COUNT(*) as incident_count 
            FROM alerts 
            GROUP BY src_ip 
            ORDER BY incident_count DESC 
            LIMIT 5
        """
        top_ips = pd.read_sql_query(top_ips_query, conn)
        print(top_ips.to_string(index=False))
        print("\n")

        # Breakdown of Alert Types
        print("--- Incident Breakdown by Type ---")
        types_query = """
            SELECT alert_type, COUNT(*) as count 
            FROM alerts 
            GROUP BY alert_type 
            ORDER BY count DESC
        """
        alert_types = pd.read_sql_query(types_query, conn)
        print(alert_types.to_string(index=False))
        print("\n=========================================")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # Ensure pandas is installed: pip install pandas
    generate_security_report()
