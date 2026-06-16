from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import SessionLocal
import database, models, schemas, auth

app = FastAPI(title="IntelliSecure: Enterprise Data Pipeline & Multi-Role Query Engine")

# Fresh dynamic initialization parameters load
models.Base.metadata.create_all(bind=database.engine)

# Cleaned automation initialization check handler
db_init = SessionLocal()
try:
    admin_exists = db_init.query(models.User).filter(models.User.username == "admin_user").first()
    if not admin_exists:
        hashed_pwd = auth.get_password_hash("password123")
        default_admin = models.User(username="admin_user", hashed_password=hashed_pwd, role="Admin")
        db_init.add(default_admin)
        db_init.commit()
finally:
    db_init.close()

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.RoleChecker(["Admin"]))):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pwd = auth.get_password_hash(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed_pwd, role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# --- ROLE-BASED PIPELINE ENDPOINTS ---

@app.get("/api/v1/admin/pipeline-config", tags=["Admin Portal"])
async def get_pipeline_configuration(current_user: models.User = Depends(auth.RoleChecker(["Admin"]))):
    return {
        "status": "success",
        "requested_by": current_user.username,
        "role": current_user.role,
        "data_pipeline_settings": {
            "engine": "IntelliSecure SQLite Engine",
            "sync_interval": "5m",
            "encryption_level": "AES-256",
            "granularity_level": "High-Density Administrative Control"
        }
    }

@app.get("/api/v1/manager/analytics", tags=["Manager Analytics"])
async def get_manager_analytics(current_user: models.User = Depends(auth.RoleChecker(["Admin", "Manager"]))):
    return {
        "status": "success",
        "requested_by": current_user.username,
        "role": current_user.role,
        "analytics_summary": {
            "total_queries_processed": 14205,
            "system_load": "24%",
            "active_sessions": 3
        }
    }

@app.get("/api/v1/employee/dashboard", tags=["Employee Dashboard"])
async def get_employee_dashboard(current_user: models.User = Depends(auth.RoleChecker(["Admin", "Manager", "Employee"]))):
    return {
        "status": "success",
        "requested_by": current_user.username,
        "role": current_user.role,
        "message": "Welcome to the IntelliSecure query console.",
        "accessible_resources": [
            "Basic query lookup",
            "Personal shift records",
            "System status checks"
        ]
    }