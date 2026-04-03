import os
import glob
from chromadb import PersistentClient
from chromadb.utils import embedding_functions
from langchain_text_splitters import MarkdownTextSplitter
from app.core.config import (
    CHROMA_DB_DIR,
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    VULHUB_ROOT,
    logger,
)
from typing import List, Dict

class VectorDBService:
    def __init__(self):
        self.client = PersistentClient(path=CHROMA_DB_DIR)
        
        # We try to use OpenAI compatible embeddings as promised in the plan
        self.embedding_function = embedding_functions.OpenAIEmbeddingFunction(
            api_key=OPENAI_API_KEY or "DUMMY_KEY",
            api_base=OPENAI_BASE_URL if OPENAI_BASE_URL else None,
            model_name="text-embedding-3-small"
        )
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name="vulhub_readmes",
            embedding_function=self.embedding_function
        )
        self.text_splitter = MarkdownTextSplitter(chunk_size=1000, chunk_overlap=100)
    
    def _read_readme(self, filepath: str) -> str:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return ""

    def index_vulhub_if_empty(self):
        """Index all Vulhub READMEs if the collection is empty."""
        try:
            if self.collection.count() > 0:
                logger.info(f"Vector DB already has {self.collection.count()} chunks. Skipping initial indexing.")
                return
            
            logger.info("Initializing Vector DB with Vulhub READMEs... This may take a while.")
            if not os.path.exists(VULHUB_ROOT):
                logger.warning("VULHUB_ROOT not found, skipping Vector DB indexing.")
                return

            documents = []
            metadatas = []
            ids = []

            # Find all README.md or README.zh-cn.md
            for root, _, files in os.walk(VULHUB_ROOT):
                for file_name in files:
                    if file_name.lower() in ["readme.md", "readme.zh-cn.md"]:
                        file_path = os.path.join(root, file_name)
                        app_cve_name = os.path.basename(root)
                        
                        content = self._read_readme(file_path)
                        if not content.strip():
                            continue
                            
                        # Split content into smaller chunks
                        chunks = self.text_splitter.split_text(content)
                        for i, chunk in enumerate(chunks):
                            if not chunk.strip():
                                continue
                            documents.append(chunk)
                            metadatas.append({
                                "source": file_path,
                                "app_name": app_cve_name,
                                "type": "vulhub_readme"
                            })
                            ids.append(f"{app_cve_name}_{file_name}_{i}")

            if documents:
                # Add in batches to avoid overwhelming the embedding API
                batch_size = 100
                for i in range(0, len(documents), batch_size):
                    self.collection.add(
                        documents=documents[i:i+batch_size],
                        metadatas=metadatas[i:i+batch_size],
                        ids=ids[i:i+batch_size]
                    )
                logger.info(f"Successfully indexed {len(documents)} chunks into Vector DB.")
            else:
                logger.info("No README files found to index.")
        except Exception as e:
            logger.error(f"Error during vector db indexing: {e}. If the Embedding API doesn't support text-embedding-3-small, consider switching to default mini-LM.")

    def search(self, query: str, n_results: int = 3) -> List[Dict]:
        """Search for relevant content based on a query."""
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            extracted_results = []
            if results and 'documents' in results and len(results['documents']) > 0:
                for i in range(len(results['documents'][0])):
                    extracted_results.append({
                        "content": results['documents'][0][i],
                        "metadata": results['metadatas'][0][i],
                        "distance": results['distances'][0][i] if 'distances' in results and results['distances'] else 0
                    })
            return extracted_results
        except Exception as e:
            logger.error(f"Vector search failed for query '{query}': {e}")
            return []

vector_db = VectorDBService()
