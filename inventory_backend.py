"""
inventory_backend.py

SQLite backend for Spare Parts Inventory Management.

- Creates inventory.db with two tables: items, transactions.
- Provides functions for adding/updating/deleting items,
  recording receive/issue transactions, searching, and generating PDF reports.
- Intended for testing in Jupyter or to be wired into a GUI (Kivy) later.
"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

# reportlab for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# ----------------- Configuration -----------------
DB_FILE = 'inventory.db'
REPORTS_DIR = 'reports'
Path(REPORTS_DIR).mkdir(exist_ok=True)

# ----------------- Database helpers -----------------
def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create the required tables if they don't exist."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS items (
            item_id TEXT PRIMARY KEY,
            item_name TEXT NOT NULL,
            unit_cost REAL NOT NULL DEFAULT 0.0,
            quantity_in_stock INTEGER NOT NULL DEFAULT 0,
            min_stock INTEGER NOT NULL DEFAULT 0,
            date_received TEXT
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id TEXT NOT NULL,
            action_type TEXT NOT NULL CHECK(action_type IN ('Receive', 'Issue')),
            quantity INTEGER NOT NULL,
            issued_to TEXT,
            branch TEXT,
            note TEXT,
            date TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(item_id)
        );
    ''')
    conn.commit()
    conn.close()

# ----------------- Item CRUD -----------------
def add_item(item_id, item_name, unit_cost, quantity=0, min_stock=0, date_received=None):
    conn = get_conn()
    cur = conn.cursor()
    
    # Check if item already exists
    cur.execute('SELECT * FROM items WHERE item_id = ?', (item_id,))
    existing = cur.fetchone()

    if existing:
        # Item exists → Update quantity and log a receive transaction
        new_quantity = existing['quantity_in_stock'] + quantity
        cur.execute('''
            UPDATE items 
            SET quantity_in_stock = ?, 
                unit_cost = ?, 
                min_stock = ?, 
                date_received = ?
            WHERE item_id = ?
        ''', (new_quantity, unit_cost or existing['unit_cost'], 
              min_stock or existing['min_stock'], 
              date_received or existing['date_received'], 
              item_id))
        
        conn.commit()
        _log_transaction(item_id, 'Receive', quantity, None, None, note='Auto-added to existing stock')
        conn.close()
        print(f"[INFO] Existing item '{item_id}' updated. New quantity: {new_quantity}")
        return
    
    # Otherwise, insert new item
    cur.execute('''
        INSERT INTO items (item_id, item_name, unit_cost, quantity_in_stock, min_stock, date_received)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (item_id, item_name, unit_cost, quantity, min_stock, date_received))
    conn.commit()
    conn.close()
    
    _log_transaction(item_id, 'Receive', quantity, None, None, note='New item added')
    print(f"[INFO] New item '{item_id}' added successfully.")

def update_item(item_id: str, item_name: Optional[str] = None, unit_cost: Optional[float] = None,
                quantity: Optional[int] = None, min_stock: Optional[int] = None,
                date_received: Optional[str] = None) -> None:
    """Update fields for an existing item. Only non-None values are updated."""
    if date_received:
        try:
            datetime.strptime(date_received, '%Y-%m-%d')
        except ValueError:
            raise ValueError('date_received must be YYYY-MM-DD or None')

    fields = []
    params = []
    if item_name is not None:
        fields.append('item_name = ?'); params.append(item_name)
    if unit_cost is not None:
        fields.append('unit_cost = ?'); params.append(float(unit_cost))
    if quantity is not None:
        fields.append('quantity_in_stock = ?'); params.append(int(quantity))
    if min_stock is not None:
        fields.append('min_stock = ?'); params.append(int(min_stock))
    if date_received is not None:
        fields.append('date_received = ?'); params.append(date_received)

    if not fields:
        return  # nothing to update

    params.append(item_id)
    sql = f'UPDATE items SET {", ".join(fields)} WHERE item_id = ?'
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(sql, tuple(params))
    conn.commit()
    conn.close()

def delete_item(item_id: str) -> None:
    """
    Delete an item from items table.
    Note: transactions remain for audit (you might choose to archive instead).
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('DELETE FROM items WHERE item_id = ?', (item_id,))
    conn.commit()
    conn.close()

def get_item(item_id: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM items WHERE item_id = ?', (item_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)

def list_items() -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM items ORDER BY item_id')
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- Transactions: Receive / Issue -----------------
def _log_transaction(item_id: str, action_type: str, quantity: int,
                     issued_to: Optional[str], branch: Optional[str],
                     note: Optional[str], when: Optional[str] = None) -> None:
    when = when or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO transactions (item_id, action_type, quantity, issued_to, branch, note, date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (item_id, action_type, int(quantity), issued_to, branch, note, when))
    conn.commit()
    conn.close()

def receive_item(item_id: str, quantity: int, note: Optional[str] = None,
                 date: Optional[str] = None) -> None:
    """Increase stock and log a 'Receive' transaction."""
    if quantity <= 0:
        raise ValueError('quantity must be positive')
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT quantity_in_stock FROM items WHERE item_id = ?', (item_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise ValueError('item_id does not exist')
    new_qty = row['quantity_in_stock'] + int(quantity)
    cur.execute('UPDATE items SET quantity_in_stock = ? WHERE item_id = ?', (new_qty, item_id))
    conn.commit()
    conn.close()
    _log_transaction(item_id, 'Receive', quantity, None, None, note, date)

def issue_item(item_id: str, quantity: int, issued_to: Optional[str] = None,
               branch: Optional[str] = None, note: Optional[str] = None,
               date: Optional[str] = None) -> None:
    """Decrease stock (if available) and log an 'Issue' transaction."""
    if quantity <= 0:
        raise ValueError('quantity must be positive')
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT quantity_in_stock FROM items WHERE item_id = ?', (item_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise ValueError('item_id does not exist')
    current = int(row['quantity_in_stock'])
    if current < quantity:
        conn.close()
        raise ValueError(f'Not enough stock: have {current}, requested {quantity}')
    new_qty = current - int(quantity)
    cur.execute('UPDATE items SET quantity_in_stock = ? WHERE item_id = ?', (new_qty, item_id))
    conn.commit()
    conn.close()
    _log_transaction(item_id, 'Issue', quantity, issued_to, branch, note, date)

def list_transactions(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    sql = 'SELECT * FROM transactions ORDER BY date DESC'
    if limit:
        sql += f' LIMIT {int(limit)}'
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def transactions_for_item(item_id: str) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM transactions WHERE item_id = ? ORDER BY date DESC', (item_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- Search & alerts -----------------
def search_items_by_id(item_id: str) -> Optional[Dict[str, Any]]:
    return get_item(item_id)

def search_items_by_name(substr: str) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    wildcard = f'%{substr}%'
    cur.execute('SELECT * FROM items WHERE item_name LIKE ? ORDER BY item_id', (wildcard,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def low_stock_items() -> List[Dict[str, Any]]:
    """Return list of items where quantity_in_stock < min_stock."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM items WHERE quantity_in_stock < min_stock ORDER BY item_id')
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- Reporting (PDF) -----------------
def generate_inventory_pdf(output_dir: str = REPORTS_DIR) -> str:
    """
    Generate a PDF report of all items and low stock list.
    Returns the absolute path to the created PDF.
    """
    items = list_items()
    total_value = sum(it['unit_cost'] * it['quantity_in_stock'] for it in items)
    low = [it for it in items if it['quantity_in_stock'] < it['min_stock']]

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    Path(output_dir).mkdir(exist_ok=True)
    pdf_path = os.path.abspath(os.path.join(output_dir, f'inventory_report_{timestamp}.pdf'))

    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph('Inventory Report', styles['Title']))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', styles['Normal']))
    elements.append(Paragraph(f'Total stock value: {total_value:.2f}', styles['Normal']))
    elements.append(Spacer(1, 12))

    # full list table
    data = [['Item ID', 'Name', 'Qty', 'Unit Cost', 'Total Cost', 'Min Stock', 'Date Received']]
    for it in items:
        data.append([
            it['item_id'],
            it['item_name'],
            str(it['quantity_in_stock']),
            f"{it['unit_cost']:.2f}",
            f"{(it['unit_cost'] * it['quantity_in_stock']):.2f}",
            str(it['min_stock']),
            it['date_received'] or ''
        ])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (2, 1), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
    ]))
    elements.append(Paragraph('Full Inventory', styles['Heading2']))
    elements.append(table)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph('Low stock items', styles['Heading2']))
    if low:
        ldata = [['Item ID', 'Name', 'Qty', 'Min Stock']]
        for it in low:
            ldata.append([it['item_id'], it['item_name'], str(it['quantity_in_stock']), str(it['min_stock'])])
        ltable = Table(ldata)
        ltable.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.red)]))
        elements.append(ltable)
    else:
        elements.append(Paragraph('None', styles['Normal']))

    doc.build(elements)
    return pdf_path

# ----------------- Helpful quick-tests for Jupyter -----------------
def _demo_seed():
    """Seed DB with sample items for manual testing (non-destructive if ids different)."""
    init_db()
    sample = [
        ('SP001', 'Ball Valve 1/2"', 12.0, 50, 10, '2025-10-01'),
        ('SP002', 'Gasket Large', 2.5, 200, 20, '2025-10-03'),
        ('SP003', 'Hydraulic Hose', 45.0, 10, 5, '2025-09-25'),
    ]
    conn = get_conn()
    cur = conn.cursor()
    for item_id, name, cost, qty, min_s, d in sample:
        try:
            cur.execute('INSERT INTO items (item_id, item_name, unit_cost, quantity_in_stock, min_stock, date_received) VALUES (?, ?, ?, ?, ?, ?)',
                        (item_id, name, cost, qty, min_s, d))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

# ----------------- End of module -----------------
if __name__ == '__main__':
    # quick interactive CLI for testing (optional)
    print("Simple inventory backend tester.")
    init_db()
    print("Database initialized:", DB_FILE)
    print("Seed sample data? (y/n) ", end='')
    if input().strip().lower().startswith('y'):
        _demo_seed()
        print("Seeded sample items.")
    print("You can now import this module in Jupyter and call functions like add_item(), list_items(), generate_inventory_pdf().")