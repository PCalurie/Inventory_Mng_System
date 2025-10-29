# backend.py
# FastAPI backend for Spare Parts Inventory Management

import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi.responses import FileResponse
import tempfile
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (Column, Integer, String, Float, DateTime, Text,
                        create_engine, ForeignKey)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from reportlab.platypus import Image as ReportLabImage
from PIL import Image as PILImage

# ---- Config ----

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./inventory.db')

if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

if DATABASE_URL.startswith('sqlite'):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SECRET_KEY = os.getenv("SECRET_KEY", "change_this_secret_to_a_strong_random_value")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# ---- SQLAlchemy setup ----
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---- Password hashing ----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---- OAuth2 token scheme ----
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ---- Models ----
class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")  # "admin" or "user"
    created_at = Column(DateTime, default=datetime.utcnow)

class Item(Base):
    __tablename__ = "items"
    item_id = Column(String, primary_key=True, index=True)  # e.g., SP001
    item_name = Column(String, nullable=False)
    unit_cost = Column(Float, nullable=False, default=0.0)
    quantity_in_stock = Column(Integer, nullable=False, default=0)
    min_stock = Column(Integer, nullable=False, default=0)
    date_received = Column(String, nullable=True)  # YYYY-MM-DD

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    item_id = Column(String, ForeignKey("items.item_id"), nullable=False)
    action_type = Column(String, nullable=False)  # "Receive" or "Issue"
    quantity = Column(Integer, nullable=False)
    issued_to = Column(String, nullable=True)
    branch = Column(String, nullable=True)
    from_location = Column(String, nullable=True)
    note = Column(Text, nullable=True)
    created_by = Column(String, ForeignKey("users.username"), nullable=True)
    date = Column(String, nullable=False)  # ISO timestamp

    item = relationship("Item", backref="transactions")
    user = relationship("User", foreign_keys=[created_by])

# ---- Pydantic schemas ----
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "user"

class UserOut(BaseModel):
    username: str
    role: str

class ItemCreate(BaseModel):
    item_id: str
    item_name: str
    unit_cost: float
    quantity: int = 0
    min_stock: int = 0
    date_received: Optional[str] = None

class ItemUpdate(BaseModel):
    item_name: Optional[str]
    unit_cost: Optional[float]
    quantity: Optional[int]
    min_stock: Optional[int]
    date_received: Optional[str]

class TransactionCreate(BaseModel):
    item_id: str
    action_type: str  # "Receive" or "Issue"
    quantity: int
    issued_to: Optional[str] = None
    branch: Optional[str] = None
    from_location: Optional[str] = None
    note: Optional[str] = None
    date: Optional[str] = None  # if omitted, filled by server

class ItemOut(BaseModel):
    item_id: str
    item_name: str
    unit_cost: float
    quantity_in_stock: int
    min_stock: int
    date_received: Optional[str]

class TransactionOut(BaseModel):
    id: int
    item_id: str
    action_type: str
    quantity: int
    issued_to: Optional[str]
    branch: Optional[str]
    from_location: Optional[str]
    note: Optional[str]
    created_by: Optional[str]
    date: str

    class Config:
        orm_mode = True

# ---- Utilities ----
def create_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(pw):
    return pwd_context.hash(pw)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username)
    if user is None:
        raise credentials_exception
    return user

async def get_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Requires admin role")
    return current_user

def add_logo_to_pdf(elements):
    """Try to find and add logo to PDF using the same method as Streamlit"""
    try:
        # Same method as your Streamlit code
        logo_path = os.path.join(os.path.dirname(__file__), "bimtech-logo.jpeg")
        
        # Check if file exists and is valid
        if os.path.exists(logo_path):
            # Use PIL to open and validate the image
            pil_image = PILImage.open(logo_path)
            
            # Convert to ReportLab Image
            logo = ReportLabImage(logo_path, width=500, height=80)
            elements.append(logo)
            elements.append(Spacer(1, 12))
            return True
    except Exception as e:
        print(f"Logo not found or invalid: {e}")
    return False

def safe_password_hash(password: str) -> str:
    """Safely hash password handling bcrypt's 72-byte limit"""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    safe_password = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.hash(safe_password)
# ---- App ----
app = FastAPI(title="Inventory API")

# allow CORS from localhost dev frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Startup: create tables and ensure admin exists ----
@app.on_event("startup")
def startup():
    create_tables()
    # create default admin if none exists
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.role == "admin").first()
        if not admin:
            default_admin = User(username="BimtechAdmin", hashed_password=safe_password_hash("Simo2025"), role="admin")
            db.add(default_admin)
            db.commit()
            print("Created default admin: username=Bimtechadmin password=Simo2025 (change it!)")
    finally:
        db.close()

# ---- Auth endpoints ----
@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users", response_model=UserOut)
def create_user(user_in: UserCreate, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    if get_user(db, user_in.username):
        raise HTTPException(status_code=400, detail="User already exists")
    user = User(username=user_in.username, hashed_password=get_password_hash(user_in.password), role=user_in.role)
    db.add(user)
    db.commit()
    return {"username": user.username, "role": user.role}

# ---- User Management Endpoints ----
@app.get("/users", response_model=List[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    """List all users (admin only)"""
    users = db.query(User).order_by(User.username).all()
    return [{"username": user.username, "role": user.role} for user in users]

@app.delete("/users/{username}")
def delete_user(username: str, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    """Delete a user (admin only)"""
    if username == admin.username:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return {"detail": f"User {username} deleted successfully"}

@app.put("/users/{username}/role")
def update_user_role(
    username: str, 
    role_update: dict,  # Expecting {"role": "admin" or "user"}
    db: Session = Depends(get_db), 
    admin: User = Depends(get_admin_user)
):
    """Update user role (admin only)"""
    if username == admin.username:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if role_update.get("role") not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    
    user.role = role_update["role"]
    db.commit()
    return {"detail": f"User {username} role updated to {role_update['role']}"}

@app.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}

# ---- Items endpoints ----
@app.post("/items", response_model=ItemOut)
def add_item_endpoint(item: ItemCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # If exists, treat as receive: add quantity & log transaction
    existing = db.query(Item).filter(Item.item_id == item.item_id).first()
    if existing:
        # update fields optionally
        existing.item_name = item.item_name or existing.item_name
        existing.unit_cost = item.unit_cost or existing.unit_cost
        existing.min_stock = item.min_stock or existing.min_stock
        existing.date_received = item.date_received or existing.date_received
        existing.quantity_in_stock = existing.quantity_in_stock + int(item.quantity)
        db.add(existing)
        db.commit()
        # log receive
        txn = Transaction(item_id=item.item_id, action_type="Receive", quantity=int(item.quantity),
                          created_by=current_user.username, date=item.date_received or datetime.utcnow().isoformat(),
                          note="Auto-receive via POST /items")
        db.add(txn)
        db.commit()
        return ItemOut(
            item_id=existing.item_id,
            item_name=existing.item_name,
            unit_cost=existing.unit_cost,
            quantity_in_stock=existing.quantity_in_stock,
            min_stock=existing.min_stock,
            date_received=existing.date_received
        )
    # create new item
    new = Item(
        item_id=item.item_id,
        item_name=item.item_name,
        unit_cost=float(item.unit_cost),
        quantity_in_stock=int(item.quantity),
        min_stock=int(item.min_stock),
        date_received=item.date_received
    )
    db.add(new)
    db.commit()
    # log receive
    txn = Transaction(item_id=item.item_id, action_type="Receive", quantity=int(item.quantity),
                      created_by=current_user.username, date=item.date_received or datetime.utcnow().isoformat(),
                      note="Initial create")
    db.add(txn)
    db.commit()
    return ItemOut(
        item_id=new.item_id,
        item_name=new.item_name,
        unit_cost=new.unit_cost,
        quantity_in_stock=new.quantity_in_stock,
        min_stock=new.min_stock,
        date_received=new.date_received
    )

@app.get("/items", response_model=List[ItemOut])
def list_items(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = db.query(Item).order_by(Item.item_id).all()
    return [ItemOut(item_id=r.item_id, item_name=r.item_name, unit_cost=r.unit_cost,
                    quantity_in_stock=r.quantity_in_stock, min_stock=r.min_stock, date_received=r.date_received) for r in rows]

@app.get("/items/{item_id}", response_model=ItemOut)
def get_item_endpoint(item_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    it = db.query(Item).filter(Item.item_id == item_id).first()
    if not it:
        raise HTTPException(status_code=404, detail="Item not found")
    return ItemOut(item_id=it.item_id, item_name=it.item_name, unit_cost=it.unit_cost,
                   quantity_in_stock=it.quantity_in_stock, min_stock=it.min_stock, date_received=it.date_received)

@app.put("/items/{item_id}", response_model=ItemOut)
def update_item_endpoint(item_id: str, payload: ItemUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    it = db.query(Item).filter(Item.item_id == item_id).first()
    if not it:
        raise HTTPException(status_code=404, detail="Item not found")
    if payload.item_name is not None:
        it.item_name = payload.item_name
    if payload.unit_cost is not None:
        it.unit_cost = float(payload.unit_cost)
    if payload.quantity is not None:
        it.quantity_in_stock = int(payload.quantity)
    if payload.min_stock is not None:
        it.min_stock = int(payload.min_stock)
    if payload.date_received is not None:
        it.date_received = payload.date_received
    db.add(it)
    db.commit()
    return ItemOut(item_id=it.item_id, item_name=it.item_name, unit_cost=it.unit_cost,
                   quantity_in_stock=it.quantity_in_stock, min_stock=it.min_stock, date_received=it.date_received)

@app.delete("/items/{item_id}")
def delete_item_endpoint(item_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can delete items")

    it = db.query(Item).filter(Item.item_id == item_id).first()
    if not it:
        raise HTTPException(status_code=404, detail="Item not found")

    # Check transactions - FIXED LOGIC
    txn_count = db.query(Transaction).filter(Transaction.item_id == item_id).count()
    if txn_count > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete item with {txn_count} existing transactions. Delete transactions first."
        )
    
    db.delete(it)
    db.commit()
    return {"detail": f"Item {item_id} deleted successfully"}

# ---- Transaction Management ----

# ---- Transactions endpoints ----
@app.post("/transactions", response_model=TransactionOut)
def create_transaction(payload: TransactionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if payload.action_type not in ("Receive", "Issue"):
        raise HTTPException(status_code=400, detail="action_type must be 'Receive' or 'Issue'")
    it = db.query(Item).filter(Item.item_id == payload.item_id).first()
    if not it:
        raise HTTPException(status_code=404, detail="Item not found")
    if payload.action_type == "Receive":
        it.quantity_in_stock = it.quantity_in_stock + int(payload.quantity)
    else:  # Issue
        if it.quantity_in_stock < int(payload.quantity):
            raise HTTPException(status_code=400, detail=f"Not enough stock: have {it.quantity_in_stock}")
        it.quantity_in_stock = it.quantity_in_stock - int(payload.quantity)
    db.add(it)
    db.commit()
    txn = Transaction(
        item_id=payload.item_id,
        action_type=payload.action_type,
        quantity=int(payload.quantity),
        issued_to=payload.issued_to,
        branch=payload.branch,
        from_location=payload.from_location,
        note=payload.note,
        created_by=current_user.username,
        date=payload.date or datetime.utcnow().isoformat()
    )
    db.add(txn)
    db.commit()
    return TransactionOut(id=txn.id, item_id=txn.item_id, action_type=txn.action_type, quantity=txn.quantity,
                          issued_to=txn.issued_to, branch=txn.branch, from_location=txn.from_location, note=txn.note, created_by=txn.created_by, date=txn.date)

@app.get("/transactions", response_model=List[TransactionOut])
def list_transactions(limit: Optional[int] = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    q = db.query(Transaction).order_by(Transaction.date.desc())
    if limit:
        q = q.limit(int(limit))
    rows = q.all()
    return [TransactionOut(id=r.id, item_id=r.item_id, action_type=r.action_type, quantity=r.quantity,
                           issued_to=r.issued_to, branch=r.branch, from_location=r.from_location, note=r.note, created_by=r.created_by, date=r.date) for r in rows]

@app.get("/transactions/{item_id}", response_model=List[TransactionOut])
def transactions_for_item(item_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = db.query(Transaction).filter(Transaction.item_id == item_id).order_by(Transaction.date.desc()).all()
    return [TransactionOut(id=r.id, item_id=r.item_id, action_type=r.action_type, quantity=r.quantity,
                           issued_to=r.issued_to, branch=r.branch, from_location=r.from_location, note=r.note, created_by=r.created_by, date=r.date) for r in rows]

@app.get("/transactions/item/{item_id}", response_model=List[TransactionOut])
def get_transactions_by_item(
    item_id: str, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """Get all transactions for a specific item"""
    transactions = db.query(Transaction).filter(Transaction.item_id == item_id).order_by(Transaction.date.desc()).all()
    return transactions

@app.delete("/transactions/{transaction_id}")
def delete_transaction(
    transaction_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a transaction (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can delete transactions")

    # Find the transaction
    txn = db.query(Transaction).filter(Transaction.id == transaction_id).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    # Find the related item
    item = db.query(Item).filter(Item.item_id == txn.item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Related item not found")

    # Reverse the transaction's effect on stock
    if txn.action_type == "Receive":
        # Subtract from stock (since we're removing a receive transaction)
        item.quantity_in_stock = max(0, item.quantity_in_stock - txn.quantity)
    elif txn.action_type == "Issue":
        # Add back to stock (since we're removing an issue transaction)
        item.quantity_in_stock = item.quantity_in_stock + txn.quantity

    # Save the item stock update
    db.add(item)
    # Delete the transaction
    db.delete(txn)
    db.commit()

    return {
        "detail": f"Transaction {transaction_id} deleted successfully. Stock for {txn.item_id} updated."
    }

# ---- Search & low stock ----
@app.get("/search")
def search(q: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # search by id exact or name substring
    rows = db.query(Item).filter((Item.item_id == q) | (Item.item_name.ilike(f"%{q}%"))).all()
    return [{"item_id": r.item_id, "item_name": r.item_name, "quantity_in_stock": r.quantity_in_stock,
             "min_stock": r.min_stock, "unit_cost": r.unit_cost, "date_received": r.date_received} for r in rows]

@app.get("/low_stock")
def low_stock(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = db.query(Item).filter(Item.quantity_in_stock <= Item.min_stock).order_by(Item.item_id).all()
    return [{"item_id": r.item_id, "item_name": r.item_name, "quantity_in_stock": r.quantity_in_stock, "min_stock": r.min_stock} for r in rows]

# ---- Reporting (PDF) ----
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

@app.post("/report/inventory")
def generate_inventory_report(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    items = db.query(Item).order_by(Item.item_id).all()
    transactions = db.query(Transaction).order_by(Transaction.date.desc()).all()

    total_value = sum((it.unit_cost or 0.0) * (it.quantity_in_stock or 0) for it in items)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.abspath(os.path.join(REPORTS_DIR, f"inventory_report_{timestamp}.pdf"))

    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elems = []
    elems.append(Paragraph("Inventory Report", styles["Title"]))
    elems.append(Spacer(1, 8))
    elems.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elems.append(Spacer(1, 8))
    elems.append(Paragraph(f"Total stock value: {total_value:.2f}", styles["Normal"]))
    elems.append(Spacer(1, 12))

    # Items table
    data = [["Item ID", "Name", "Qty", "Unit Cost", "Total Cost", "Min Stock", "Date Received"]]
    for it in items:
        data.append([it.item_id, it.item_name, str(it.quantity_in_stock), f"{it.unit_cost:.2f}", f"{(it.unit_cost or 0.0)*(it.quantity_in_stock or 0):.2f}", str(it.min_stock), it.date_received or ""])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.grey), ("TEXTCOLOR",(0,0),(-1,0),colors.whitesmoke), ("GRID",(0,0),(-1,-1),0.5,colors.black), ("BACKGROUND",(0,1),(-1,-1),colors.beige)]))
    elems.append(Paragraph("Full Inventory", styles["Heading2"]))
    elems.append(table)
    elems.append(Spacer(1,12))

    # Transactions (recent)
    elems.append(Paragraph("Recent Transactions (descending)", styles["Heading2"]))
    tdata = [["Date","Item ID","Action","Qty","Issued To","Branch","By","Note"]]
    for t in transactions[:200]:  # limit to recent 200
        tdata.append([t.date, t.item_id, t.action_type, str(t.quantity), t.issued_to or "", t.branch or "", t.created_by or "", t.note or ""])
    ttable = Table(tdata)
    ttable.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.3,colors.black)]))
    elems.append(ttable)

    doc.build(elems)
    return {"path": pdf_path}

@app.get("/export/pdf")
def export_pdf(
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user),
    item_id: Optional[str] = None,
    low_stock_only: bool = False,
    include_transactions: bool = True,
    transaction_limit: int = 50
):
    """Generate PDF report with optional filters"""
    
    try:
        # Create temporary file
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        filename = temp.name

        # Query data with filters
        items_query = db.query(Item).order_by(Item.item_id)
        
        # Apply filters
        if item_id:
            items_query = items_query.filter(Item.item_id == item_id)
        
        if low_stock_only:
            items_query = items_query.filter(Item.quantity_in_stock <= Item.min_stock)
        
        items = items_query.all()
        
        # Query transactions with filters
        transactions_query = db.query(Transaction).order_by(Transaction.date.desc())
        
        if item_id:
            transactions_query = transactions_query.filter(Transaction.item_id == item_id)
        
        transactions = transactions_query.limit(transaction_limit).all()

        # Start PDF
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elems = []

        # ---- Header with Logo ----
        try:
            logo_added = add_logo_to_pdf(elems)
        except:
            logo_added = False

        report_date = datetime.now().strftime('%Y-%m-%d')
        
        # Dynamic header based on filters
        report_title = "BIMTECH INVENTORY REPORT"
        if item_id:
            report_title = f"ITEM REPORT - {item_id}"
        elif low_stock_only:
            report_title = "LOW STOCK ALERT REPORT"
        
        elems.append(Paragraph(f"<b>{report_title}</b>", styles["Title"]))
        elems.append(Spacer(1, 12))
        elems.append(Paragraph(f"Generated by: {current_user.username}", styles["Normal"]))
        elems.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        
        # Show filter info
        filter_info = []
        if item_id:
            filter_info.append(f"Item: {item_id}")
        if low_stock_only:
            filter_info.append("Low Stock Items Only")
        if filter_info:
            elems.append(Paragraph(f"Filters: {', '.join(filter_info)}", styles["Normal"]))
        
        elems.append(Spacer(1, 12))

        # ---- Items table ----
        if items:
            data = [["Item ID", "Item Name", "Qty", "Unit Cost", "Total Value", "Min Stock", "Status"]]
            for it in items:
                total_value = (it.unit_cost or 0) * (it.quantity_in_stock or 0)
                status = "LOW STOCK" if it.quantity_in_stock <= it.min_stock else "OK"
                
                data.append([
                    it.item_id,
                    it.item_name,
                    str(it.quantity_in_stock),
                    f"{it.unit_cost:.2f}",
                    f"{total_value:.2f}",
                    str(it.min_stock),
                    status
                ])
            
            table = Table(data, repeatRows=1)
            
            # Create table style with conditional formatting
            table_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
            
            # Add conditional row coloring
            for i, it in enumerate(items, start=1):
                if it.quantity_in_stock <= it.min_stock:
                    table_style.append(("BACKGROUND", (0, i), (-1, i), colors.orange))
                    table_style.append(("FONTNAME", (0, i), (-1, i), "Helvetica-Bold"))
            
            table.setStyle(TableStyle(table_style))
            elems.append(Paragraph("Stock Items", styles["Heading2"]))
            elems.append(table)
            elems.append(Spacer(1, 16))
        else:
            elems.append(Paragraph("No items found matching the criteria", styles["Heading2"]))
            elems.append(Spacer(1, 16))

        # ---- Transactions (Optional) ----
        if include_transactions and transactions:
            elems.append(Paragraph("Recent Transactions", styles["Heading2"]))
            tdata = [["Date", "Item ID", "Action", "Qty", "Issued To", "Branch", "By", "Note"]]
            for t in transactions:
                tdata.append([
                    t.date.split("T")[0] if "T" in t.date else t.date,
                    t.item_id,
                    t.action_type,
                    str(t.quantity),
                    t.issued_to or "",
                    t.branch or "",
                    t.created_by or "",
                    t.note or ""
                ])
            ttable = Table(tdata, repeatRows=1)
            ttable.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.3, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ]))
            elems.append(ttable)
        elif include_transactions:
            elems.append(Paragraph("No transactions found", styles["Normal"]))
            elems.append(Spacer(1, 16))

        # Footer
        elems.append(Spacer(1, 20))
        elems.append(Paragraph(f"<i>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>", styles["Normal"]))

        doc.build(elems)

        # Generate filename with context
        if item_id:
            filename_with_date = f"Item_Report_{item_id}_{report_date}.pdf"
        elif low_stock_only:
            filename_with_date = f"Low_Stock_Report_{report_date}.pdf"
        else:
            filename_with_date = f"Full_Inventory_Report_{report_date}.pdf"

        return FileResponse(
            filename,
            media_type="application/pdf",
            filename=filename_with_date
        )
    
    except Exception as e:
        # Log the actual error for debugging
        print(f"PDF Generation Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        raise HTTPException(
            status_code=500, 
            detail=f"PDF generation failed: {str(e)}"
        )

# ---- Run instructions endpoint ----
@app.get("/")
def root():
    return {"msg": "Inventory API - visit /docs for interactive API docs"}

# End of backend.py
