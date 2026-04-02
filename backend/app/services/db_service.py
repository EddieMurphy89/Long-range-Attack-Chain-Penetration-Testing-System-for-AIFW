import os
from datetime import datetime
from tinydb import TinyDB, Query
from app.models.schemas import AgentHistoryRecord
from app.core.config import logger

# Store the DB in the agent_history directory
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent_history")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "agent_history.json")

# Initialize TinyDB
db = TinyDB(DB_PATH)
history_table = db.table('agent_history')

def save_agent_history(record: AgentHistoryRecord) -> int:
    """Save a new agent history record. Returns the inserted document ID."""
    try:
        record_dict = record.model_dump()
        # Ensure we always have a current timestamp if it's missing somehow
        if not record_dict.get('timestamp'):
            record_dict['timestamp'] = datetime.now().isoformat()
            
        doc_id = history_table.insert(record_dict)
        logger.info(f"Saved agent history record: {doc_id}")
        return doc_id
    except Exception as e:
        logger.error(f"Failed to save agent history: {e}")
        return -1

def get_agent_history() -> list[AgentHistoryRecord]:
    """Retrieve all agent history records, ordered by newest first."""
    try:
        records = history_table.all()
        # Add the document ID back into the dictionary so the frontend can use it as a key
        for r in records:
            r['id'] = r.doc_id
            
        # Parse into Pydantic models for type safety, then sort by timestamp descending
        models = [AgentHistoryRecord(**r) for r in records]
        models.sort(key=lambda x: x.timestamp, reverse=True)
        return models
    except Exception as e:
        logger.error(f"Failed to retrieve agent history: {e}")
        return []
