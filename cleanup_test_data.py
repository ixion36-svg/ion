"""Clean up test KFPs and documents from DB."""
import sqlite3

DB = r"C:\Users\Tomo\ion\.ion\ion.db"
conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("DELETE FROM known_false_positives")
print(f"Deleted {cur.rowcount} KFPs")

cur.execute("DELETE FROM document_versions WHERE document_id IN (SELECT id FROM documents WHERE name LIKE 'KFP Registry%')")
print(f"Deleted {cur.rowcount} document versions")

cur.execute("DELETE FROM documents WHERE name LIKE 'KFP Registry%'")
print(f"Deleted {cur.rowcount} documents")

cur.execute("DELETE FROM collections WHERE name LIKE 'Known False Positives%'")
print(f"Deleted {cur.rowcount} collections")

conn.commit()
conn.close()
print("Cleanup done")
