import sys
from unittest.mock import MagicMock

import pytest

sys.modules.setdefault("numpy", MagicMock())

from threatsimgpt.rag.config import EmbeddingConfig, EmbeddingModel, VectorStoreConfig, VectorStoreType
from threatsimgpt.rag.models import Chunk, SearchResult
from threatsimgpt.rag.vectorstore import VectorStoreBase, VectorStoreManager


class FakeEmbeddingService:
    def __init__(self, config):
        self.config = config

    async def initialize(self):
        return None

    async def embed_text(self, text: str):
        return [0.3, 0.2, 0.1]

    async def embed_batch(self, texts):
        return [[0.3, 0.2, 0.1] for _ in texts]

    def get_stats(self):
        return {"model": self.config.model.value, "cache_hit_rate": 0.0}


class CapturingStore(VectorStoreBase):
    def __init__(self, config, results=None):
        super().__init__(config)
        self.added_chunks = []
        self.deleted_ids = []
        self._results = results or []

    async def initialize(self):
        return None

    async def add_chunks(self, chunks, embeddings):
        self.added_chunks.extend(chunks)

    async def search(self, query_embedding, top_k=10, filters=None):
        return self._results[:top_k]

    async def delete(self, ids):
        self.deleted_ids.extend(ids)

    async def get_stats(self):
        return {"store_type": self.config.store_type.value, "count": len(self.added_chunks)}


@pytest.mark.asyncio
async def test_vectorstore_manager_hybrid_flow(monkeypatch):
    from threatsimgpt.rag import vectorstore as vectorstore_module

    monkeypatch.setattr(vectorstore_module, "EmbeddingService", FakeEmbeddingService)

    chunk = Chunk(
        id="c1",
        document_id="d1",
        content="alpha",
        chunk_index=0,
        start_char=0,
        end_char=10,
        document_title="Doc A",
    )
    result = SearchResult(chunk=chunk, similarity_score=0.9)

    primary_store = CapturingStore
    secondary_store = CapturingStore

    store_builders = {
        VectorStoreType.FAISS: lambda config: primary_store(config, results=[result]),
        VectorStoreType.CHROMADB: lambda config: secondary_store(config, results=[result]),
    }

    config = VectorStoreConfig(
        store_type=VectorStoreType.FAISS,
        hybrid_store_types=[VectorStoreType.CHROMADB],
    )
    embedding_config = EmbeddingConfig(model=EmbeddingModel.SENTENCE_TRANSFORMERS)

    manager = VectorStoreManager(config, embedding_config, store_builders=store_builders)
    await manager.initialize()

    await manager.add_documents([
        {
            "id": "c1",
            "content": "alpha",
            "document_id": "d1",
            "document_title": "Doc A",
            "chunk_index": 0,
        }
    ])

    results = await manager.search("alpha", top_k=5)

    assert results
    assert results[0].chunk.id == "c1"

    await manager.delete_documents(["c1"])

    stats = await manager.get_stats()
    assert "faiss" in stats["stores"]
    assert "chromadb" in stats["stores"]
