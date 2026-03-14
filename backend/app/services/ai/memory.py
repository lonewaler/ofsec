"""
OfSec V3 — Qdrant RAG Memory
==============================
Long-term agentic memory service using Qdrant vector database.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models

logger = structlog.get_logger(__name__)


class RAGMemory:
    """Retrieval-Augmented Generation memory via Qdrant."""

    COLLECTION_NAME = "agent_memory"
    VECTOR_SIZE = 1536  # Standard size for text-embedding-ada-002 / text-embedding-3-small

    def __init__(self, host: str = "localhost", port: int = 6333):
        """Initialize connection to Qdrant."""
        self.client = AsyncQdrantClient(host=host, port=port)
        self._initialized = False

    async def _ensure_collection(self) -> None:
        """Create the agent_memory collection if it does not exist."""
        if self._initialized:
            return

        try:
            collections_response = await self.client.get_collections()
            collection_names = [c.name for c in collections_response.collections]

            if self.COLLECTION_NAME not in collection_names:
                await self.client.create_collection(
                    collection_name=self.COLLECTION_NAME,
                    vectors_config=models.VectorParams(
                        size=self.VECTOR_SIZE,
                        distance=models.Distance.COSINE
                    )
                )
                logger.info("qdrant.collection_created", collection=self.COLLECTION_NAME)
            
            self._initialized = True
        except Exception as e:
            logger.error("qdrant.initialization_error", error=str(e))
            raise

    async def store_experience(self, goal: str, command: str, result: str, success: bool, embedding: list[float]) -> None:
        """Saves a past interaction to Qdrant."""
        await self._ensure_collection()

        point_id = str(uuid.uuid4())
        payload = {
            "goal": goal,
            "command": command,
            "result": result,
            "success": success
        }

        try:
            await self.client.upsert(
                collection_name=self.COLLECTION_NAME,
                points=[
                    models.PointStruct(
                        id=point_id,
                        vector=embedding,
                        payload=payload
                    )
                ]
            )
            logger.debug("qdrant.experience_stored", point_id=point_id)
        except Exception as e:
            logger.error("qdrant.store_error", error=str(e))
            raise

    async def search_experience(self, embedding: list[float], limit: int = 3) -> list[dict[str, Any]]:
        """Searches Qdrant and returns the payload of similar past experiences."""
        await self._ensure_collection()

        try:
            search_result = await self.client.search(
                collection_name=self.COLLECTION_NAME,
                query_vector=embedding,
                limit=limit
            )

            results = []
            for hit in search_result:
                if hit.payload:
                    results.append(hit.payload)
            
            return results
        except Exception as e:
            logger.error("qdrant.search_error", error=str(e))
            return []
