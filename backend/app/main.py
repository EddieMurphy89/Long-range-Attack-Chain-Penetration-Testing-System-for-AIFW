from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as api_router
from app.api.aifw_endpoints import router as aifw_router
from app.api.mutator_endpoints import router as mutator_router
from app.api.agent_endpoints import router as agent_router
from app.api.experiment_endpoints import router as experiment_router

app = FastAPI(title="Vulhub Manager")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")
app.include_router(aifw_router, prefix="/api")
app.include_router(mutator_router, prefix="/api")
app.include_router(agent_router, prefix="/api")
app.include_router(experiment_router, prefix="/api")
