#!/usr/bin/env python3
import sqlite3

# Query A:/system/state/blackboard.db (table: blackboard_events)
conn1 = sqlite3.connect("A:/system/state/blackboard.db")
cur1 = conn1.cursor()
cur1.execute("SELECT id, event_type, source, topic, created_at, payload FROM blackboard_events WHERE event_type='SHOWCASE_UPDATED' ORDER BY id DESC LIMIT 1")
row1 = cur1.fetchone()
print("Database: A:/system/state/blackboard.db (blackboard_events)")
if row1:
    print(f"  ID: {row1[0]}")
    print(f"  Event: {row1[1]}")
    print(f"  Source: {row1[2]}")
    print(f"  Topic: {row1[3]}")
    print(f"  Created: {row1[4]}")
    print(f"  Payload: {row1[5][:120]}...")
conn1.close()

# Query A:/projects/orbit-security/data/orbit_events.db (table: events)
conn2 = sqlite3.connect("A:/projects/orbit-security/data/orbit_events.db")
cur2 = conn2.cursor()
cur2.execute("SELECT id, event_type, source, topic, created_at, payload FROM events WHERE event_type='SHOWCASE_UPDATED' ORDER BY id DESC LIMIT 1")
row2 = cur2.fetchone()
print("Database: A:/projects/orbit-security/data/orbit_events.db (events)")
if row2:
    print(f"  ID: {row2[0]}")
    print(f"  Event: {row2[1]}")
    print(f"  Source: {row2[2]}")
    print(f"  Topic: {row2[3]}")
    print(f"  Created: {row2[4]}")
    print(f"  Payload: {row2[5][:120]}...")
conn2.close()
