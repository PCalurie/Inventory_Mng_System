# inventory_ui.py
import streamlit as st
import requests
import pandas as pd
import tempfile
from PIL import Image as PILImage
from datetime import datetime
import os

API_BASE_URL = "https://inventory-backend-knf8.onrender.com"
#API_BASE_URL = "http://127.0.0.1:8000"

# 1. API Helper with Token and Error Handling
def api_call(endpoint, method='GET', data=None, files=None):
    token = st.session_state.get('token')
    headers = {}
    if token:
        headers['Authorization'] = f"Bearer {token}"
    
    if data and not files:
        headers['Content-Type'] = 'application/json'

    try:
        url = f"{API_BASE_URL}{endpoint}"
        response = requests.request(method, url, headers=headers, json=data, files=files)
        
        # Only raise for status if it's a server error, not auth errors
        if response.status_code >= 500:
            response.raise_for_status()
            
        # Handle different status codes
        if response.status_code == 204:
            return {"detail": "success"}
        elif response.status_code == 401:
            st.error("Session expired. Please login again.")
            logout()
            return None
        elif response.status_code == 403:
            st.error("You don't have permission for this action.")
            return None
        elif response.status_code >= 400:
            # Don't stop the app, just return None
            error_detail = response.json().get("detail", "Unknown error")
            st.error(f"API Error: {error_detail}")
            return None

        return response.json()
        
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to backend server. Make sure it's running on port 8000.")
        return None
    except requests.exceptions.RequestException as e:
        st.error(f"Network error: {e}")
        return None
    except Exception as e:
        st.error(f"Unexpected error: {e}")
        return None

# Initialize session state
if 'token' not in st.session_state:
    st.session_state['token'] = None
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None

# 2. Authentication UI
def login_screen():
    st.title("BIMTECH Inventory Management System Login")

    with st.form("login_form"):
        username = st.text_input("Username", value="username")
        password = st.text_input("Password", type="password", value="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            login_data = {
                'username': username,
                'password': password,
                'grant_type': 'password'
            }
            
            try:
                response = requests.post(
                    f"{API_BASE_URL}/token",
                    data=login_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    st.session_state['token'] = token_data['access_token']
                    
                    # Fetch user role
                    user_response = requests.get(
                        f"{API_BASE_URL}/me",
                        headers={'Authorization': f"Bearer {st.session_state['token']}"}
                    )
                    
                    if user_response.status_code == 200:
                        user_data = user_response.json()
                        st.session_state['user_role'] = user_data['role']
                        st.success("Login successful!")
                        user_data = api_call("/me")
                        st.session_state['user_role'] = user_data['role']
                        st.session_state['username'] = user_data['username']  # Add this line
                        st.rerun()
                    else:
                        st.error("Failed to fetch user details")
                else:
                    error_detail = response.json().get("detail", "Login failed")
                    st.error(f"Login failed: {error_detail}")
                
            except Exception as e:
                st.error(f"Connection error: {e}")

def logout():
    st.session_state['token'] = None
    st.session_state['user_role'] = None
    st.rerun()

# 3. Main Dashboard UI
def debug_connection():
    st.header("🔧 Debug Connection")
    
    # Test basic connection
    try:
        response = requests.get(f"{API_BASE_URL}/")
        st.success(f"✅ Backend is reachable: {response.status_code}")
        st.json(response.json())
    except Exception as e:
        st.error(f"❌ Cannot reach backend: {e}")
        return
    
    # Test items endpoint without auth
    try:
        response = requests.get(f"{API_BASE_URL}/items")
        st.write(f"Items endpoint (no auth): {response.status_code}")
        if response.status_code != 200:
            st.json(response.json())
    except Exception as e:
        st.error(f"Items endpoint error: {e}")
    
    # Check if user is logged in
    st.write(f"Token in session: {'Yes' if st.session_state.get('token') else 'No'}")
    st.write(f"User role: {st.session_state.get('user_role')}")

# Add this temporarily to your dashboard function
    
    # ... rest of your existing dashboard code ...
def dashboard():
    # Logo Header
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "bimtech-logo.jpg")
        letterhead = PILImage.open(logo_path)
        
        col1, col2 = st.columns([1, 3])
        with col1:
            st.image(letterhead, width='stretch')
        with col2:
            st.title("BIMTECH Inventory Management System")
            st.write(f"User: {st.session_state.get('user_role', 'User')}")
            
    except Exception as e:
        # Fallback header without logo
        st.title("BIMTECH Inventory Management System")

    st.sidebar.title("Navigation")
    
    # User info
    st.sidebar.write(f"Logged in as: **{st.session_state.get('user_role', 'Unknown')}**")

    if st.sidebar.button("Debug Connection"):
        debug_connection()
        return

    if st.sidebar.button("Logout"):
        logout()
        return

    # Navigation
    pages = ["Inventory Overview", "Add/Receive Stock", "Issue Stock", "Transaction History"]
    
    # Only show Admin Tools for admin users
    if st.session_state.get('user_role') == 'admin':
        pages.append("Admin Tools")
    
    page = st.sidebar.radio("Go to", pages)
    
    if page == "Inventory Overview":
        inventory_overview()
    elif page == "Add/Receive Stock":
        add_or_receive_stock()
    elif page == "Issue Stock":
        issue_stock()
    elif page == "Transaction History":
        transaction_history()
    elif page == "Admin Tools":
        admin_tools()


def inventory_overview():
    st.header("Inventory Overview")
    
    # Fetch Data with better error handling
    st.write("📡 Loading inventory data...")
    items = api_call("/items")
    
    if items is None:
        st.error("""
        ❌ Failed to load inventory data. Possible reasons:
        - Backend server is not running
        - Authentication token expired
        - Network connection issue
        
        Try these fixes:
        1. Make sure your FastAPI backend is running: `uvicorn backend:app --reload`
        2. Check if you can access: http://127.0.0.1:8000/docs
        3. Try logging out and back in
        """)
        return
        
    if not items:  # Empty list
        st.info("No items in inventory. Add some items first!")
        return

    # Calculate Metrics
    df = pd.DataFrame(items)
    df['Total Value'] = df['unit_cost'] * df['quantity_in_stock']
    low_stock_df = df[df['quantity_in_stock'] <= df['min_stock']]
    
    # Display metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Items", len(df))
    col2.metric("Low Stock Items", len(low_stock_df), delta_color="inverse")
    col3.metric("Total Inventory Value", f"Ksh{df['Total Value'].sum():,.2f}")

    st.subheader("Current Stock List")
    
    # Low Stock Warning
    if not low_stock_df.empty:
        st.warning(f"🚨 {len(low_stock_df)} items are at or below minimum stock threshold!")
        st.dataframe(low_stock_df[['item_id', 'item_name', 'quantity_in_stock', 'min_stock']], hide_index=True)
    
    # Main Inventory Table with styling
    def highlight_low_stock(row):
        if row['quantity_in_stock'] <= row['min_stock']:
            return ['background-color: #ffcccc'] * len(row)
        else:
            return [''] * len(row)
    
    display_df = df[['item_id', 'item_name', 'quantity_in_stock', 'min_stock', 'unit_cost', 'Total Value']].copy()
    styled_df = display_df.style.apply(highlight_low_stock, axis=1)
    
    st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            'unit_cost': st.column_config.NumberColumn("Unit Cost", format="Ksh%.2f"),
            'Total Value': st.column_config.NumberColumn("Total Value", format="Ksh%.2f"),
        }
    )
    
    # ---- PDF DOWNLOAD SECTION ----
    st.markdown("---")
    st.subheader("📊 Generate PDF Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Quick Reports**")
        if st.button("📄 Download Full Inventory PDF", type="primary"):
            with st.spinner("Generating PDF report..."):
                download_pdf_report()
        
        if st.button("🚨 Low Stock Alert PDF"):
            with st.spinner("Generating low stock report..."):
                download_pdf_report(low_stock_only=True)
    
    with col2:
        st.write("**Custom Item Report**")
        item_ids = [item['item_id'] for item in items]
        selected_item = st.selectbox("Select Item", [""] + item_ids)
        
        if st.button("📋 Generate Item Report") and selected_item:
            with st.spinner(f"Generating report for {selected_item}..."):
                download_pdf_report(item_id=selected_item)

def add_or_receive_stock():
    st.header("Add New Item or Receive Stock")
    st.info("If the Item ID exists, the quantity will be added. If new, the item will be created.")
    
    with st.form("add_item_form"):
        item_id = st.text_input("Item ID (e.g., SP001)", help="Unique identifier for the part.")
        item_name = st.text_input("Item Name")
        unit_cost = st.number_input("Unit Cost", min_value=0.01, format="%.2f")
        quantity = st.number_input("Quantity to Add/Initial Stock", min_value=1, step=1)
        min_stock = st.number_input("Minimum Stock Threshold", value=0, min_value=0, step=1)  # FIXED: was st.number_number
        
        submitted = st.form_submit_button("Submit")
        
        if submitted:
            if not item_id or not item_name:
                st.error("Item ID and Name are required")
                return
                
            payload = {
                "item_id": item_id,
                "item_name": item_name,
                "unit_cost": unit_cost,
                "quantity": quantity,
                "min_stock": min_stock
            }
            result = api_call("/items", method="POST", data=payload)
            if result:
                st.success(f"Item {item_id} saved/stock received successfully!")
                st.rerun()

def issue_stock():
    st.header("Issue Stock (Stock Out)")
    
    items_data = api_call("/items")
    if items_data is None:
        st.error("Failed to load items")
        return
        
    item_ids = [item['item_id'] for item in items_data]
    
    with st.form("issue_stock_form"):
        item_id = st.selectbox("Select Item ID", options=item_ids)
        quantity = st.number_input("Quantity to Issue", min_value=1, step=1)
        issued_to = st.text_input("Issued To")
        branch = st.text_input("Branch/Department")
        note = st.text_area("Note (Optional)")

        submitted = st.form_submit_button("Issue Stock")
        
        if submitted:
            payload = {
                "item_id": item_id,
                "action_type": "Issue",
                "quantity": quantity,
                "issued_to": issued_to,
                "branch": branch,
                "note": note
            }
            result = api_call("/transactions", method="POST", data=payload)
            if result:
                st.success(f"Successfully issued {quantity} units of {item_id}.")
                st.rerun()

def transaction_history():
    st.header("Recent Transactions")
    
    transactions = api_call("/transactions?limit=100")
    if transactions is None:
        st.error("Failed to load transactions")
        return
        
    if transactions:
        df = pd.DataFrame(transactions)
        # Clean up date format
        df['date'] = pd.to_datetime(df['date']).dt.strftime('%Y-%m-%d %H:%M')
        st.dataframe(
            df[['date', 'item_id', 'action_type', 'quantity', 'issued_to', 'branch', 'created_by', 'note']],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No transactions found.")

def download_pdf_report(item_id=None, low_stock_only=False, include_transactions=True, transaction_limit=50):
    """Download PDF report with filters"""
    token = st.session_state.get('token')
    
    if not token:
        st.error("Please login first")
        return
        
    try:
        # Build query parameters
        params = {}
        if item_id:
            params['item_id'] = item_id
        if low_stock_only:
            params['low_stock_only'] = 'true'
        if not include_transactions:
            params['include_transactions'] = 'false'
        if transaction_limit:
            params['transaction_limit'] = transaction_limit
        
        st.write(f"🔄 Generating PDF report with parameters: {params}")
        
        response = requests.get(
            f"{API_BASE_URL}/export/pdf", 
            headers={'Authorization': f"Bearer {token}"},
            params=params
        )
        
        if response.status_code == 200:
            # Get filename from content-disposition header or generate one
            content_disposition = response.headers.get('content-disposition', '')
            if 'filename=' in content_disposition:
                filename = content_disposition.split('filename=')[-1].strip('"')
            else:
                # Generate filename based on filters
                current_date = datetime.now().strftime('%Y-%m-%d')

                if item_id:
                    filename = f"Item_Report_{item_id}_{current_date}.pdf"
                elif low_stock_only:
                    filename = f"Low_Stock_Report_{current_date}.pdf"
                else:
                    filename = f"Inventory_Report_{current_date}.pdf"
            
            # Create download button
            st.download_button(
                label="⬇️ Click to Download PDF",
                data=response.content,
                file_name=filename,
                mime="application/pdf",
                key=f"pdf_download_{item_id or 'full'}_{datetime.now().timestamp()}"  # Unique key
            )
            st.success("✅ PDF generated successfully! Click the download button above.")
        else:
            error_detail = "Unknown error"
            try:
                error_detail = response.json().get("detail", str(response.status_code))
            except:
                error_detail = str(response.status_code)
            st.error(f"❌ Failed to generate PDF: {error_detail}")
        
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to backend server. Make sure it's running.")
    except Exception as e:
        st.error(f"❌ Unexpected error: {e}")

def admin_tools():
    st.header("🔧 Admin Tools")
    
    tab1, tab2, tab3 = st.tabs(["👥 User Management", "🗑️ Delete Items", "📊 System Info"])
    
    with tab1:
        user_management()
    
    with tab2:
        delete_items()
    
    with tab3:
        system_info()

def user_management():
    st.subheader("User Management")
    
    # Add new user
    st.write("### Add New User")
    with st.form("add_user_form"):
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            new_username = st.text_input("Username")
        with col2:
            new_password = st.text_input("Password", type="password")
        with col3:
            new_role = st.selectbox("Role", ["user", "admin"])
        
        if st.form_submit_button("Add User"):
            if new_username and new_password:
                payload = {
                    "username": new_username,
                    "password": new_password,
                    "role": new_role
                }
                result = api_call("/users", method="POST", data=payload)
                if result:
                    st.success(f"User {new_username} created successfully!")
                    st.rerun()
            else:
                st.error("Username and password are required")
    
    st.markdown("---")
    
    # List and manage existing users
    st.write("### Existing Users")
    users = api_call("/users")
    
    if users:
        for user in users:
            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
            with col1:
                st.write(f"**{user['username']}**")
            with col2:
                st.write(f"`{user['role']}`")
            with col3:
                if user['username'] != st.session_state.get('username'):
                    # Role update
                    if user['role'] == 'admin':
                        if st.button("Make User", key=f"demote_{user['username']}"):
                            result = api_call(f"/users/{user['username']}/role", method="PUT", data={"role": "user"})
                            if result:
                                st.success(result.get("detail", "Role updated"))
                                st.rerun()
                    else:
                        if st.button("Make Admin", key=f"promote_{user['username']}"):
                            result = api_call(f"/users/{user['username']}/role", method="PUT", data={"role": "admin"})
                            if result:
                                st.success(result.get("detail", "Role updated"))
                                st.rerun()
            with col4:
                if user['username'] != st.session_state.get('username'):
                    if st.button("🗑️ Delete", key=f"delete_{user['username']}"):
                        result = api_call(f"/users/{user['username']}", method="DELETE")
                        if result:
                            st.success(result.get("detail", "User deleted"))
                            st.rerun()
    else:
        st.info("No users found")

def delete_items():
    st.subheader("Delete Items")
    st.warning("⚠️ Items can only be deleted if they have no transactions.")
    
    # Fetch all items
    items = api_call("/items")
    
    if items:
        st.write("### Current Inventory Items")
        
        for item in items:
            col1, col2, col3, col4, col5 = st.columns([3, 2, 2, 1, 1])
            with col1:
                st.write(f"**{item['item_name']}**")
                st.write(f"ID: `{item['item_id']}`")
            with col2:
                st.write(f"Stock: **{item['quantity_in_stock']}**")
            with col3:
                st.write(f"Min: {item['min_stock']}")
            with col4:
                # Check if item has transactions
                transactions = api_call(f"/transactions/{item['item_id']}")
                has_transactions = transactions and len(transactions) > 0
                
                if has_transactions:
                    st.error(f"Has {len(transactions)} transactions")
                else:
                    st.success("No transactions")
            with col5:
                if not has_transactions:
                    if st.button("Delete", key=f"del_{item['item_id']}", type="secondary"):
                        result = api_call(f"/items/{item['item_id']}", method="DELETE")
                        if result:
                            st.success(f"Item {item['item_id']} deleted successfully!")
                            st.rerun()
                else:
                    if st.button("View Transactions", key=f"view_{item['item_id']}"):
                        st.session_state[f"show_txns_{item['item_id']}"] = True
            
            # Show transactions for this item if requested
            if st.session_state.get(f"show_txns_{item['item_id']}"):
                show_item_transactions(item['item_id'])
        
        st.markdown("---")
        
        # Transaction Management Section
        st.write("### Transaction Management")
        manage_transactions()

def show_item_transactions(item_id):
    """Show transactions for a specific item with delete options"""
    st.write(f"#### Transactions for {item_id}")
    
    transactions = api_call(f"/transactions/{item_id}")
    if transactions:
        df = pd.DataFrame(transactions)
        for _, txn in df.iterrows():
            col1, col2, col3, col4, col5 = st.columns([2, 1, 2, 2, 1])
            with col1:
                st.write(f"**{txn['date']}**")
            with col2:
                st.write(f"**{txn['action_type']}**")
            with col3:
                st.write(f"Qty: {txn['quantity']}")
            with col4:
                st.write(f"By: {txn.get('created_by', 'Unknown')}")
            with col5:
                if st.button("🗑️", key=f"del_txn_{txn['id']}"):
                    result = api_call(f"/transactions/{txn['id']}", method="DELETE")
                    if result:
                        st.success("Transaction deleted!")
                        st.rerun()
    else:
        st.info("No transactions found for this item")

def manage_transactions():
    """Manage all transactions with filtering and bulk operations"""
    st.write("#### All Transactions")
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        filter_type = st.selectbox("Filter by type", ["All", "Receive", "Issue"])
    with col2:
        limit = st.number_input("Show last N transactions", min_value=10, max_value=500, value=100)
    
    # Fetch transactions
    transactions = api_call(f"/transactions?limit={limit}")
    
    if transactions:
        # Apply filters
        if filter_type != "All":
            transactions = [t for t in transactions if t['action_type'] == filter_type]
        
        st.write(f"Showing {len(transactions)} transactions")
        
        # Display transactions with delete options
        for txn in transactions:
            col1, col2, col3, col4, col5, col6 = st.columns([2, 1, 1, 2, 2, 1])
            with col1:
                st.write(f"**{txn['date'].split('T')[0] if 'T' in txn['date'] else txn['date']}**")
            with col2:
                st.write(f"`{txn['item_id']}`")
            with col3:
                st.write(f"**{txn['action_type']}**")
            with col4:
                st.write(f"Qty: {txn['quantity']}")
            with col5:
                st.write(f"By: {txn.get('created_by', 'Unknown')}")
            with col6:
                if st.button("Delete", key=f"del_all_txn_{txn['id']}", type="secondary"):
                    result = api_call(f"/transactions/{txn['id']}", method="DELETE")
                    if result:
                        st.success("Transaction deleted!")
                        st.rerun()
    else:
        st.info("No transactions found")

def system_info():
    st.subheader("System Information")
    
    # Basic system info
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Backend Status**")
        try:
            response = requests.get(f"{API_BASE_URL}/")
            if response.status_code == 200:
                st.success("✅ Online")
            else:
                st.error("�️ Offline")
        except:
            st.error("❌ Unreachable")
    
    with col2:
        st.write("**Database**")
        items = api_call("/items")
        users = api_call("/users")
        
        if items is not None and users is not None:
            st.write(f"Items: {len(items)}")
            st.write(f"Users: {len(users)}")
        else:
            st.write("Data unavailable")
    
    # Quick stats
    st.markdown("---")
    st.write("**Quick Actions**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Refresh All Data"):
            st.rerun()
    
    with col2:
        if st.button("📊 Generate System Report"):
            download_pdf_report()

def main():
    st.set_page_config(page_title="BIMTECH Inventory Management System", layout="wide")
    
    if st.session_state['token'] is None:
        login_screen()
    else:
        dashboard()

if __name__ == "__main__":
    main()
