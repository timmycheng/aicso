"""向量存储层 - 基于ChromaDB"""
from __future__ import annotations

from typing import Optional

import structlog

logger = structlog.get_logger()


class VectorStore:
    """向量存储，用于知识检索和案例相似度匹配"""

    def __init__(self, path: str = "./data/chromadb", collection_name: str = "cases"):
        self.path = path
        self.collection_name = collection_name
        self._client = None
        self._collection = None

    async def connect(self) -> None:
        try:
            import chromadb
            self._client = chromadb.PersistentClient(path=self.path)
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            logger.info("vector_store.connected", path=self.path, collection=self.collection_name)
        except ImportError:
            logger.warning("vector_store.chromadb_not_installed", msg="pip install chromadb")
        except Exception as e:
            logger.warning("vector_store.connect_failed", error=str(e))

    async def add_document(
        self,
        doc_id: str,
        text: str,
        metadata: Optional[dict] = None,
    ) -> None:
        if not self._collection:
            return
        try:
            self._collection.add(
                ids=[doc_id],
                documents=[text],
                metadatas=[metadata or {}],
            )
        except Exception as e:
            logger.error("vector_store.add_failed", doc_id=doc_id, error=str(e))

    async def search(
        self,
        query: str,
        top_k: int = 5,
        score_threshold: float = 0.7,
    ) -> list[dict]:
        if not self._collection:
            return []
        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=top_k,
            )
            items = []
            for i, doc_id in enumerate(results["ids"][0]):
                distance = results["distances"][0][i] if results["distances"] else 1.0
                similarity = 1.0 - distance
                if similarity >= score_threshold:
                    items.append({
                        "id": doc_id,
                        "document": results["documents"][0][i],
                        "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                        "similarity": similarity,
                    })
            return items
        except Exception as e:
            logger.error("vector_store.search_failed", error=str(e))
            return []

    async def close(self) -> None:
        self._client = None
        self._collection = None
