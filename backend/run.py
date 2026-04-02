import uvicorn
import sys
import os

# Add local directory to path mainly so finding 'app' works if not installed
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import from the new location
from app.main import app

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
