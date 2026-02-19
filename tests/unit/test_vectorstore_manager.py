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
        self.initialized = False

    async def initialize(self):
        self.initialized = True

    async def embed_text(self, text: str):
        return [0.1, 0.2, 0.3]

    async def embed_batch(self, texts):
        return [[0.1, 0.2, 0.3] for _ in texts]

    def get_stats(self):
        return {
            "model": self.config.model.value,
            "cache_hit_rate": 0.0,
        }


class FakeStore(VectorStoreBase):
    def __init__(self, config, results=None):
        super().__init__(config)
        self._results = results or []
        self.added_chunks = []
        self.deleted_ids = []

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


class FailingStore(VectorStoreBase):
    def __init__(self, config, error: Exception):
        super().__init__(config)
        self._error = error

    async def initialize(self):
        return None

    async def add_chunks(self, chunks, embeddings):
        return None

    async def search(self, query_embedding, top_k=10, filters=None):
        raise self._error

    async def delete(self, ids):
        return None

    async def get_stats(self):
        return {"store_type": self.config.store_type.value, "count": 0}


@pytest.mark.asyncio
async def test_vectorstore_manager_hybrid_merges_results(monkeypatch):
    from threatsimgpt.rag import vectorstore as vectorstore_module

    monkeypatch.setattr(vectorstore_module, "EmbeddingService", FakeEmbeddingService)

    chunk_a = Chunk(
        id="c1",
        document_id="d1",
        content="alpha",
        chunk_index=0,
        start_char=0,
        end_char=10,
        document_title="Doc A",
    )
    chunk_b = Chunk(
        id="c2",
        document_id="d2",
        content="beta",
        chunk_index=0,
        start_char=0,
        end_char=10,
        document_title="Doc B",
    )
    chunk_c = Chunk(
        id="c3",
        document_id="d3",
        content="gamma",
        chunk_index=0,
        start_char=0,
        end_char=10,
        document_title="Doc C",
    )

    primary_results = [
        SearchResult(chunk=chunk_a, similarity_score=0.9),
        SearchResult(chunk=chunk_b, similarity_score=0.8),
    ]
    secondary_results = [
        SearchResult(chunk=chunk_a, similarity_score=0.4),
        SearchResult(chunk=chunk_c, similarity_score=0.95),
    ]

    def build_primary(config):
        return FakeStore(config, results=primary_results)

    def build_secondary(config):
        return FakeStore(config, results=secondary_results)

    store_builders = {
        VectorStoreType.FAISS: build_primary,
        VectorStoreType.CHROMADB: build_secondary,
    }

    config = VectorStoreConfig(
        store_type=VectorStoreType.FAISS,
        hybrid_store_types=[VectorStoreType.CHROMADB],
    )
    embedding_config = EmbeddingConfig(model=EmbeddingModel.SENTENCE_TRANSFORMERS)

    manager = VectorStoreManager(config, embedding_config, store_builders=store_builders)
    await manager.initialize()

    results = await manager.search("test", top_k=3)

    assert [r.chunk.id for r in results] == ["c3", "c1", "c2"]
    assert "store_sources" in results[0].chunk.metadata
    assert set(results[0].chunk.metadata["store_sources"]) == {"chromadb"}


@pytest.mark.asyncio
async def test_vectorstore_manager_stats_include_embeddings(monkeypatch):
    from threatsimgpt.rag import vectorstore as vectorstore_module

    monkeypatch.setattr(vectorstore_module, "EmbeddingService", FakeEmbeddingService)

    def build_store(config):
        return FakeStore(config)

    store_builders = {VectorStoreType.FAISS: build_store}

    config = VectorStoreConfig(store_type=VectorStoreType.FAISS)
    embedding_config = EmbeddingConfig(model=EmbeddingModel.SENTENCE_TRANSFORMERS)

    manager = VectorStoreManager(config, embedding_config, store_builders=store_builders)
    await manager.initialize()

    stats = await manager.get_stats()

    assert "stores" in stats
    assert "embeddings" in stats
    assert stats["embeddings"]["model"] == EmbeddingModel.SENTENCE_TRANSFORMERS.value


@pytest.mark.asyncio
async def test_vectorstore_manager_handles_store_failure(monkeypatch):
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
    primary_results = [SearchResult(chunk=chunk, similarity_score=0.6)]

    store_builders = {
        VectorStoreType.FAISS: lambda config: FakeStore(config, results=primary_results),
        VectorStoreType.CHROMADB: lambda config: FailingStore(config, error=RuntimeError("boom")),
    }

    config = VectorStoreConfig(
        store_type=VectorStoreType.FAISS,
        hybrid_store_types=[VectorStoreType.CHROMADB],
    )
    embedding_config = EmbeddingConfig(model=EmbeddingModel.SENTENCE_TRANSFORMERS)

    manager = VectorStoreManager(config, embedding_config, store_builders=store_builders)
    await manager.initialize()

    results = await manager.search("test", top_k=3)

    assert results
    assert results[0].chunk.id == "c1"
    assert results[0].combined_score == 0.6
