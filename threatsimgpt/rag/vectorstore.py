"""
RAG Vector Store Manager
========================

Manages vector storage and embedding operations for the RAG system.
Supports multiple backends: Neo4j (primary), FAISS, ChromaDB.

Neo4j provides:
- Native vector search with graph context
- Relationship-aware threat intelligence
- MITRE ATT&CK technique linking
- CVE to technique correlation
"""

import asyncio
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from .models import Chunk, SearchResult
from .config import VectorStoreConfig, EmbeddingConfig, EmbeddingModel

logger = logging.getLogger(__name__)


# ==========================================
# Embedding Service
# ==========================================

class EmbeddingService:
    """
    Service for generating text embeddings.

    Supports multiple embedding models from OpenAI, Cohere,
    and local models via sentence-transformers.
    """

    def __init__(self, config: EmbeddingConfig):
        self.config = config
        self._model = None
        self._client = None
        self._cache: Dict[str, List[float]] = {}

    async def initialize(self):
        """Initialize the embedding model."""
        model = self.config.model

        if model in [EmbeddingModel.OPENAI_SMALL, EmbeddingModel.OPENAI_LARGE, EmbeddingModel.OPENAI_ADA]:
            await self._init_openai()
        elif model in [EmbeddingModel.COHERE_ENGLISH, EmbeddingModel.COHERE_MULTILINGUAL]:
            await self._init_cohere()
        else:
            await self._init_sentence_transformers()

    async def _init_openai(self):
        """Initialize OpenAI client."""
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=self.config.api_key)
            logger.info(f"Initialized OpenAI embedding model: {self.config.model.value}")
        except ImportError:
            raise RuntimeError("OpenAI package not installed. Run: pip install openai")

    async def _init_cohere(self):
        """Initialize Cohere client."""
        try:
            import cohere
            self._client = cohere.Client(self.config.api_key)
            logger.info(f"Initialized Cohere embedding model: {self.config.model.value}")
        except ImportError:
            raise RuntimeError("Cohere package not installed. Run: pip install cohere")

    async def _init_sentence_transformers(self):
        """Initialize local sentence-transformers model."""
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.config.model.value)
            logger.info(f"Initialized local embedding model: {self.config.model.value}")
        except ImportError:
            raise RuntimeError("sentence-transformers not installed. Run: pip install sentence-transformers")

    async def embed_text(self, text: str) -> List[float]:
        """Generate embedding for a single text."""
        # Check cache
        cache_key = self._cache_key(text)
        if self.config.cache_embeddings and cache_key in self._cache:
            return self._cache[cache_key]

        embedding = await self._generate_embedding([text])
        embedding = embedding[0]

        # Normalize if configured
        if self.config.normalize:
            embedding = self._normalize(embedding)

        # Cache
        if self.config.cache_embeddings:
            self._cache[cache_key] = embedding

        return embedding

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        # Check cache for each text
        cached_results = {}
        uncached_texts = []
        uncached_indices = []

        for i, text in enumerate(texts):
            cache_key = self._cache_key(text)
            if self.config.cache_embeddings and cache_key in self._cache:
                cached_results[i] = self._cache[cache_key]
            else:
                uncached_texts.append(text)
                uncached_indices.append(i)

        # Generate embeddings for uncached texts
        if uncached_texts:
            new_embeddings = await self._generate_embedding(uncached_texts)

            for idx, embedding in zip(uncached_indices, new_embeddings):
                if self.config.normalize:
                    embedding = self._normalize(embedding)
                cached_results[idx] = embedding

                # Cache
                if self.config.cache_embeddings:
                    cache_key = self._cache_key(texts[idx])
                    self._cache[cache_key] = embedding

        # Reconstruct results in original order
        return [cached_results[i] for i in range(len(texts))]

    async def _generate_embedding(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using the configured model."""
        model = self.config.model

        if model in [EmbeddingModel.OPENAI_SMALL, EmbeddingModel.OPENAI_LARGE, EmbeddingModel.OPENAI_ADA]:
            return await self._openai_embed(texts)
        elif model in [EmbeddingModel.COHERE_ENGLISH, EmbeddingModel.COHERE_MULTILINGUAL]:
            return await self._cohere_embed(texts)
        else:
            return self._local_embed(texts)

    async def _openai_embed(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using OpenAI."""
        # Process in batches
        all_embeddings = []

        for i in range(0, len(texts), self.config.batch_size):
            batch = texts[i:i + self.config.batch_size]

            response = await self._client.embeddings.create(
                model=self.config.model.value,
                input=batch
            )

            batch_embeddings = [item.embedding for item in response.data]
            all_embeddings.extend(batch_embeddings)

        return all_embeddings

    async def _cohere_embed(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using Cohere."""
        response = self._client.embed(
            texts=texts,
            model=self.config.model.value,
            input_type="search_document"
        )
        return response.embeddings

    def _local_embed(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using local model."""
        embeddings = self._model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()

    def _normalize(self, embedding: List[float]) -> List[float]:
        """L2 normalize embedding vector."""
        arr = np.array(embedding)
        norm = np.linalg.norm(arr)
        if norm > 0:
            arr = arr / norm
        return arr.tolist()

    def _cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()  # nosec B324

    def clear_cache(self):
        """Clear embedding cache."""
        self._cache.clear()


# ==========================================
# Vector Store Base
# ==========================================

class VectorStoreBase(ABC):
    """Abstract base class for vector stores."""

    def __init__(self, config: VectorStoreConfig):
        self.config = config

    @abstractmethod
    async def initialize(self):
        """Initialize the vector store."""
        pass

    @abstractmethod
    async def add_chunks(self, chunks: List[Dict[str, Any]], embeddings: List[List[float]]):
        """Add chunks with embeddings to the store."""
        pass

    @abstractmethod
    async def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """Search for similar chunks."""
        pass

    @abstractmethod
    async def delete(self, ids: List[str]):
        """Delete chunks by ID."""
        pass

    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get vector store statistics."""
        pass


# ==========================================
# Neo4j Vector Store Implementation (Primary)
# ==========================================

class Neo4jStore(VectorStoreBase):
    """
    Neo4j vector store implementation.

    Leverages Neo4j's native vector search with graph capabilities
    for relationship-aware threat intelligence retrieval.

    Features:
    - Vector similarity search with cosine/euclidean distance
    - Graph-based context enrichment
    - MITRE ATT&CK technique relationships
    - CVE to threat actor correlations
    - Temporal threat evolution tracking
    """

    def __init__(self, config: VectorStoreConfig):
        super().__init__(config)
        self._driver = None
        self._database = config.collection_name or "neo4j"

    async def initialize(self):
        """Initialize Neo4j connection and vector index."""
        try:
            from neo4j import AsyncGraphDatabase

            # Build connection URI
            uri = f"bolt://{self.config.host}:{self.config.port}"

            # Get credentials from config or environment
            import os
            username = os.environ.get("NEO4J_USERNAME", "neo4j")
            password = os.environ.get("NEO4J_PASSWORD", "")

            if not password:
                password = self.config.api_key or ""

            # Create async driver
            self._driver = AsyncGraphDatabase.driver(
                uri,
                auth=(username, password),
                max_connection_lifetime=3600,
            )

            # Verify connection
            async with self._driver.session(database=self._database) as session:
                result = await session.run("RETURN 1 as test")
                await result.consume()

            # Create vector index if not exists
            await self._create_vector_index()

            # Create graph schema for threat intelligence
            await self._create_schema()

            logger.info(f"Initialized Neo4j vector store: {uri}")

        except ImportError:
            raise RuntimeError("Neo4j driver not installed. Run: pip install neo4j")
        except Exception as e:
            raise RuntimeError(f"Failed to connect to Neo4j: {e}")

    async def _create_vector_index(self):
        """Create vector search index in Neo4j."""
        dimensions = self.config.ef_construction or 1536  # Default OpenAI dimensions

        # Neo4j vector index creation query
        index_query = """
        CREATE VECTOR INDEX chunk_embeddings IF NOT EXISTS
        FOR (c:Chunk)
        ON (c.embedding)
        OPTIONS {
            indexConfig: {
                `vector.dimensions`: $dimensions,
                `vector.similarity_function`: $similarity
            }
        }
        """

        similarity = "cosine" if self.config.distance_metric == "cosine" else "euclidean"

        async with self._driver.session(database=self._database) as session:
            try:
                await session.run(
                    index_query,
                    dimensions=dimensions,
                    similarity=similarity
                )
                logger.info(f"Created vector index with {dimensions} dimensions")
            except Exception as e:
                # Index might already exist
                logger.debug(f"Vector index creation: {e}")

    async def _create_schema(self):
        """Create graph schema for threat intelligence."""
        schema_queries = [
            # Constraints for unique IDs
            "CREATE CONSTRAINT chunk_id IF NOT EXISTS FOR (c:Chunk) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT document_id IF NOT EXISTS FOR (d:Document) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (v:CVE) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT threat_actor_id IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.id IS UNIQUE",

            # Indexes for common queries
            "CREATE INDEX chunk_source IF NOT EXISTS FOR (c:Chunk) ON (c.source_url)",
            "CREATE INDEX chunk_created IF NOT EXISTS FOR (c:Chunk) ON (c.created_at)",
            "CREATE INDEX technique_tactic IF NOT EXISTS FOR (t:Technique) ON (t.tactic)",
        ]

        async with self._driver.session(database=self._database) as session:
            for query in schema_queries:
                try:
                    await session.run(query)
                except Exception as e:
                    logger.debug(f"Schema creation: {e}")

    async def add_chunks(self, chunks: List[Dict[str, Any]], embeddings: List[List[float]]):
        """Add chunks with embeddings to Neo4j."""
        if not chunks:
            return

        # Batch insert query with MERGE for idempotency
        insert_query = """
        UNWIND $chunks AS chunk
        MERGE (c:Chunk {id: chunk.id})
        SET c.content = chunk.content,
            c.document_id = chunk.document_id,
            c.source_url = chunk.source_url,
            c.document_title = chunk.document_title,
            c.chunk_index = chunk.chunk_index,
            c.embedding = chunk.embedding,
            c.created_at = datetime()

        WITH c, chunk

        // Link to Document node
        MERGE (d:Document {id: chunk.document_id})
        SET d.title = chunk.document_title,
            d.source_url = chunk.source_url
        MERGE (c)-[:FROM_DOCUMENT]->(d)

        // Extract and link MITRE techniques if present
        WITH c, chunk
        WHERE chunk.technique_ids IS NOT NULL
        UNWIND chunk.technique_ids AS tech_id
        MERGE (t:Technique {id: tech_id})
        MERGE (c)-[:REFERENCES_TECHNIQUE]->(t)

        RETURN count(c) as created
        """

        # Prepare chunks with embeddings
        chunk_data = []
        for chunk, embedding in zip(chunks, embeddings):
            chunk_data.append({
                "id": chunk["id"],
                "content": chunk["content"],
                "document_id": chunk.get("document_id", ""),
                "source_url": chunk.get("source_url", ""),
                "document_title": chunk.get("document_title", ""),
                "chunk_index": chunk.get("chunk_index", 0),
                "embedding": embedding,
                "technique_ids": chunk.get("technique_ids"),
            })

        # Execute batch insert
        async with self._driver.session(database=self._database) as session:
            result = await session.run(insert_query, chunks=chunk_data)
            summary = await result.consume()
            logger.info(f"Added {len(chunks)} chunks to Neo4j")

    async def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """
        Search Neo4j using vector similarity.

        Optionally enriches results with graph context.
        """
        # Build filter clause
        filter_clause = ""
        filter_params = {}

        if filters:
            conditions = []
            if "source_url" in filters:
                conditions.append("c.source_url = $source_url")
                filter_params["source_url"] = filters["source_url"]
            if "document_id" in filters:
                conditions.append("c.document_id = $document_id")
                filter_params["document_id"] = filters["document_id"]
            if conditions:
                filter_clause = "WHERE " + " AND ".join(conditions)

        # Vector search query with optional graph enrichment
        search_query = f"""
        CALL db.index.vector.queryNodes('chunk_embeddings', $top_k, $embedding)
        YIELD node AS c, score
        {filter_clause}

        // Optionally get related techniques
        OPTIONAL MATCH (c)-[:REFERENCES_TECHNIQUE]->(t:Technique)

        // Get source document
        OPTIONAL MATCH (c)-[:FROM_DOCUMENT]->(d:Document)

        RETURN c.id AS id,
               c.content AS content,
               c.document_id AS document_id,
               c.source_url AS source_url,
               c.document_title AS document_title,
               c.chunk_index AS chunk_index,
               c.created_at AS created_at,
               score,
               collect(DISTINCT t.id) AS techniques,
               d.title AS doc_title
        ORDER BY score DESC
        LIMIT $top_k
        """

        search_results = []

        async with self._driver.session(database=self._database) as session:
            result = await session.run(
                search_query,
                embedding=query_embedding,
                top_k=top_k,
                **filter_params
            )

            records = await result.data()

            for record in records:
                chunk = Chunk(
                    id=record["id"],
                    document_id=record["document_id"] or "",
                    content=record["content"],
                    chunk_index=record["chunk_index"] or 0,
                    start_char=0,
                    end_char=0,
                    source_url=record["source_url"] or "",
                    document_title=record["document_title"] or "",
                    created_at=record.get("created_at"),
                    metadata={
                        "techniques": record.get("techniques", []),
                    }
                )

                search_results.append(SearchResult(
                    chunk=chunk,
                    similarity_score=float(record["score"]),
                ))

        return search_results

    async def search_with_graph_context(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        expand_techniques: bool = True,
        expand_cves: bool = True
    ) -> List[SearchResult]:
        """
        Advanced search with graph traversal for richer context.

        Expands results to include related techniques, CVEs,
        and threat actors through graph relationships.
        """
        # First, get vector search results
        base_results = await self.search(query_embedding, top_k=top_k)

        if not expand_techniques and not expand_cves:
            return base_results

        # Enrich with graph context
        enrichment_query = """
        MATCH (c:Chunk {id: $chunk_id})

        // Get related techniques
        OPTIONAL MATCH (c)-[:REFERENCES_TECHNIQUE]->(t:Technique)
        OPTIONAL MATCH (t)-[:PART_OF_TACTIC]->(tac:Tactic)

        // Get related CVEs
        OPTIONAL MATCH (c)-[:MENTIONS_CVE]->(v:CVE)
        OPTIONAL MATCH (v)-[:EXPLOITS]->(t2:Technique)

        // Get threat actors using these techniques
        OPTIONAL MATCH (a:ThreatActor)-[:USES_TECHNIQUE]->(t)

        RETURN collect(DISTINCT {
            technique_id: t.id,
            technique_name: t.name,
            tactic: tac.name
        }) AS techniques,
        collect(DISTINCT {
            cve_id: v.id,
            severity: v.severity,
            description: v.description
        }) AS cves,
        collect(DISTINCT a.name) AS threat_actors
        """

        async with self._driver.session(database=self._database) as session:
            for result in base_results:
                try:
                    enrichment = await session.run(
                        enrichment_query,
                        chunk_id=result.chunk.id
                    )
                    record = await enrichment.single()

                    if record and result.chunk.metadata:
                        result.chunk.metadata["techniques"] = record["techniques"]
                        result.chunk.metadata["cves"] = record["cves"]
                        result.chunk.metadata["threat_actors"] = record["threat_actors"]
                except Exception as e:
                    logger.debug(f"Graph enrichment failed: {e}")

        return base_results

    async def add_technique_relationship(
        self,
        chunk_id: str,
        technique_id: str,
        relationship_type: str = "REFERENCES_TECHNIQUE"
    ):
        """Add a relationship between a chunk and a MITRE technique."""
        query = """
        MATCH (c:Chunk {id: $chunk_id})
        MERGE (t:Technique {id: $technique_id})
        MERGE (c)-[r:REFERENCES_TECHNIQUE]->(t)
        SET r.created_at = datetime()
        RETURN c, t
        """

        async with self._driver.session(database=self._database) as session:
            await session.run(
                query,
                chunk_id=chunk_id,
                technique_id=technique_id
            )

    async def add_cve_relationship(self, chunk_id: str, cve_id: str, severity: str = ""):
        """Add a relationship between a chunk and a CVE."""
        query = """
        MATCH (c:Chunk {id: $chunk_id})
        MERGE (v:CVE {id: $cve_id})
        SET v.severity = $severity
        MERGE (c)-[r:MENTIONS_CVE]->(v)
        SET r.created_at = datetime()
        RETURN c, v
        """

        async with self._driver.session(database=self._database) as session:
            await session.run(
                query,
                chunk_id=chunk_id,
                cve_id=cve_id,
                severity=severity
            )

    async def delete(self, ids: List[str]):
        """Delete chunks by ID."""
        query = """
        UNWIND $ids AS id
        MATCH (c:Chunk {id: id})
        DETACH DELETE c
        """

        async with self._driver.session(database=self._database) as session:
            await session.run(query, ids=ids)
            logger.info(f"Deleted {len(ids)} chunks from Neo4j")

    async def get_stats(self) -> Dict[str, Any]:
        """Get Neo4j vector store statistics."""
        stats_query = """
        MATCH (c:Chunk)
        WITH count(c) AS chunk_count

        OPTIONAL MATCH (d:Document)
        WITH chunk_count, count(d) AS doc_count

        OPTIONAL MATCH (t:Technique)
        WITH chunk_count, doc_count, count(t) AS technique_count

        OPTIONAL MATCH (v:CVE)
        RETURN chunk_count, doc_count, technique_count, count(v) AS cve_count
        """

        async with self._driver.session(database=self._database) as session:
            result = await session.run(stats_query)
            record = await result.single()

            return {
                "store_type": "neo4j",
                "database": self._database,
                "host": self.config.host,
                "port": self.config.port,
                "chunk_count": record["chunk_count"] if record else 0,
                "document_count": record["doc_count"] if record else 0,
                "technique_count": record["technique_count"] if record else 0,
                "cve_count": record["cve_count"] if record else 0,
            }

    async def get_related_chunks(self, chunk_id: str, depth: int = 2) -> List[Chunk]:
        """Get chunks related through graph traversal."""
        query = """
        MATCH (c:Chunk {id: $chunk_id})
        MATCH path = (c)-[*1..$depth]-(related:Chunk)
        WHERE related <> c
        RETURN DISTINCT related.id AS id,
               related.content AS content,
               related.document_id AS document_id,
               related.source_url AS source_url,
               related.document_title AS document_title,
               related.chunk_index AS chunk_index,
               length(path) AS distance
        ORDER BY distance
        LIMIT 10
        """

        chunks = []

        async with self._driver.session(database=self._database) as session:
            result = await session.run(query, chunk_id=chunk_id, depth=depth)
            records = await result.data()

            for record in records:
                chunks.append(Chunk(
                    id=record["id"],
                    document_id=record["document_id"] or "",
                    content=record["content"],
                    chunk_index=record["chunk_index"] or 0,
                    start_char=0,
                    end_char=0,
                    source_url=record["source_url"] or "",
                    document_title=record["document_title"] or "",
                ))

        return chunks

    async def close(self):
        """Close Neo4j connection."""
        if self._driver:
            await self._driver.close()


# ==========================================
# ChromaDB Implementation (Fallback)
# ==========================================

class ChromaDBStore(VectorStoreBase):
    """ChromaDB vector store implementation."""

    def __init__(self, config: VectorStoreConfig):
        super().__init__(config)
        self._client = None
        self._collection = None

    async def initialize(self):
        """Initialize ChromaDB."""
        try:
            import chromadb
            from chromadb.config import Settings

            # Create persistent client
            self._client = chromadb.Client(Settings(
                chroma_db_impl="duckdb+parquet",
                persist_directory=self.config.persist_directory,
                anonymized_telemetry=False
            ))

            # Get or create collection
            self._collection = self._client.get_or_create_collection(
                name=self.config.collection_name,
                metadata={"hnsw:space": self.config.distance_metric}
            )

            logger.info(f"Initialized ChromaDB collection: {self.config.collection_name}")

        except ImportError:
            raise RuntimeError("ChromaDB not installed. Run: pip install chromadb")

    async def add_chunks(self, chunks: List[Dict[str, Any]], embeddings: List[List[float]]):
        """Add chunks to ChromaDB."""
        if not chunks:
            return

        ids = [c["id"] for c in chunks]
        documents = [c["content"] for c in chunks]
        metadatas = [{
            "document_id": c.get("document_id", ""),
            "source_url": c.get("source_url", ""),
            "document_title": c.get("document_title", ""),
            "chunk_index": c.get("chunk_index", 0),
        } for c in chunks]

        self._collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )

        logger.info(f"Added {len(chunks)} chunks to ChromaDB")

    async def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """Search ChromaDB."""
        where = filters if filters else None

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where,
            include=["documents", "metadatas", "distances"]
        )

        search_results = []

        if results["ids"] and results["ids"][0]:
            for i, id_ in enumerate(results["ids"][0]):
                # Convert distance to similarity
                distance = results["distances"][0][i] if results["distances"] else 0
                # ChromaDB returns L2 distance, convert to similarity
                similarity = 1 / (1 + distance)

                chunk = Chunk(
                    id=id_,
                    document_id=results["metadatas"][0][i].get("document_id", ""),
                    content=results["documents"][0][i] if results["documents"] else "",
                    chunk_index=results["metadatas"][0][i].get("chunk_index", 0),
                    start_char=0,
                    end_char=0,
                    source_url=results["metadatas"][0][i].get("source_url", ""),
                    document_title=results["metadatas"][0][i].get("document_title", ""),
                )

                search_results.append(SearchResult(
                    chunk=chunk,
                    similarity_score=similarity,
                ))

        return search_results

    async def delete(self, ids: List[str]):
        """Delete from ChromaDB."""
        self._collection.delete(ids=ids)

    async def get_stats(self) -> Dict[str, Any]:
        """Get ChromaDB stats."""
        return {
            "collection_name": self.config.collection_name,
            "count": self._collection.count(),
            "persist_directory": self.config.persist_directory,
        }


# ==========================================
# FAISS Implementation
# ==========================================

class FAISSStore(VectorStoreBase):
    """FAISS vector store implementation."""

    def __init__(self, config: VectorStoreConfig):
        super().__init__(config)
        self._index = None
        self._id_map: Dict[int, str] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}
        self._documents: Dict[str, str] = {}
        self._next_id = 0

    async def initialize(self):
        """Initialize FAISS index."""
        try:
            import faiss

            # Create index based on distance metric
            dimensions = 1536  # Default for OpenAI

            if self.config.distance_metric == "cosine":
                self._index = faiss.IndexFlatIP(dimensions)  # Inner product for cosine
            else:
                self._index = faiss.IndexFlatL2(dimensions)

            # Load existing index if available
            index_path = Path(self.config.persist_directory) / "faiss.index"
            if index_path.exists():
                self._index = faiss.read_index(str(index_path))
                self._load_metadata()

            logger.info("Initialized FAISS index")

        except ImportError:
            raise RuntimeError("FAISS not installed. Run: pip install faiss-cpu")

    def _load_metadata(self):
        """Load metadata from disk."""
        meta_path = Path(self.config.persist_directory) / "metadata.json"
        if meta_path.exists():
            with open(meta_path, 'r') as f:
                data = json.load(f)
                self._id_map = {int(k): v for k, v in data.get("id_map", {}).items()}
                self._metadata = data.get("metadata", {})
                self._documents = data.get("documents", {})
                self._next_id = data.get("next_id", 0)

    def _save_metadata(self):
        """Save metadata to disk."""
        import faiss

        Path(self.config.persist_directory).mkdir(parents=True, exist_ok=True)

        # Save index
        index_path = Path(self.config.persist_directory) / "faiss.index"
        faiss.write_index(self._index, str(index_path))

        # Save metadata
        meta_path = Path(self.config.persist_directory) / "metadata.json"
        with open(meta_path, 'w') as f:
            json.dump({
                "id_map": self._id_map,
                "metadata": self._metadata,
                "documents": self._documents,
                "next_id": self._next_id,
            }, f)

    async def add_chunks(self, chunks: List[Dict[str, Any]], embeddings: List[List[float]]):
        """Add chunks to FAISS."""
        if not chunks:
            return

        # Convert to numpy array
        vectors = np.array(embeddings).astype('float32')

        # Normalize for cosine similarity
        if self.config.distance_metric == "cosine":
            faiss_module = __import__('faiss')
            faiss_module.normalize_L2(vectors)

        # Add to index
        self._index.add(vectors)

        # Store metadata
        for i, chunk in enumerate(chunks):
            faiss_id = self._next_id + i
            chunk_id = chunk["id"]

            self._id_map[faiss_id] = chunk_id
            self._documents[chunk_id] = chunk["content"]
            self._metadata[chunk_id] = {
                "document_id": chunk.get("document_id", ""),
                "source_url": chunk.get("source_url", ""),
                "document_title": chunk.get("document_title", ""),
                "chunk_index": chunk.get("chunk_index", 0),
            }

        self._next_id += len(chunks)
        self._save_metadata()

        logger.info(f"Added {len(chunks)} chunks to FAISS")

    async def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """Search FAISS index."""
        # Convert to numpy
        query_vector = np.array([query_embedding]).astype('float32')

        # Normalize for cosine similarity
        if self.config.distance_metric == "cosine":
            faiss_module = __import__('faiss')
            faiss_module.normalize_L2(query_vector)

        # Search
        distances, indices = self._index.search(query_vector, top_k)

        search_results = []

        for i, (dist, idx) in enumerate(zip(distances[0], indices[0])):
            if idx < 0:  # FAISS returns -1 for missing results
                continue

            chunk_id = self._id_map.get(int(idx))
            if not chunk_id:
                continue

            # Convert distance to similarity
            if self.config.distance_metric == "cosine":
                similarity = float(dist)  # Already normalized
            else:
                similarity = 1 / (1 + float(dist))

            metadata = self._metadata.get(chunk_id, {})

            chunk = Chunk(
                id=chunk_id,
                document_id=metadata.get("document_id", ""),
                content=self._documents.get(chunk_id, ""),
                chunk_index=metadata.get("chunk_index", 0),
                start_char=0,
                end_char=0,
                source_url=metadata.get("source_url", ""),
                document_title=metadata.get("document_title", ""),
            )

            # Apply filters
            if filters:
                match = True
                for key, value in filters.items():
                    if metadata.get(key) != value:
                        match = False
                        break
                if not match:
                    continue

            search_results.append(SearchResult(
                chunk=chunk,
                similarity_score=similarity,
            ))

        return search_results

    async def delete(self, ids: List[str]):
        """Delete from FAISS (rebuild required)."""
        # FAISS doesn't support deletion - would need to rebuild
        logger.warning("FAISS deletion requires index rebuild - not implemented")

    async def get_stats(self) -> Dict[str, Any]:
        """Get FAISS stats."""
        return {
            "index_type": "FAISS",
            "count": self._index.ntotal,
            "dimensions": self._index.d,
            "persist_directory": self.config.persist_directory,
        }


# ==========================================
# Vector Store Manager
# ==========================================

class VectorStoreManager:
    """
    Manages vector store operations.

    Provides unified interface for different vector store backends.
    Defaults to Neo4j for graph-enhanced threat intelligence.
    """

    def __init__(
        self,
        store_config: VectorStoreConfig,
        embedding_config: EmbeddingConfig
    ):
        self.store_config = store_config
        self.embedding_config = embedding_config

        self._store: Optional[VectorStoreBase] = None
        self._embedding_service: Optional[EmbeddingService] = None

    async def initialize(self):
        """Initialize vector store and embedding service."""
        # Initialize embedding service
        self._embedding_service = EmbeddingService(self.embedding_config)
        await self._embedding_service.initialize()

        # Initialize vector store (Neo4j is default)
        store_type = self.store_config.store_type.value

        if store_type == "neo4j":
            self._store = Neo4jStore(self.store_config)
        elif store_type == "chromadb":
            self._store = ChromaDBStore(self.store_config)
        elif store_type == "faiss":
            self._store = FAISSStore(self.store_config)
        else:
            # Default to Neo4j
            logger.info(f"Unknown store type '{store_type}', defaulting to Neo4j")
            self._store = Neo4jStore(self.store_config)

        await self._store.initialize()

        logger.info(f"Initialized VectorStoreManager with {store_type}")

    async def add_documents(self, chunks: List[Dict[str, Any]]):
        """Add document chunks to the vector store."""
        if not chunks:
            return

        # Generate embeddings
        texts = [c["content"] for c in chunks]
        embeddings = await self._embedding_service.embed_batch(texts)

        # Add to store
        await self._store.add_chunks(chunks, embeddings)

    async def search(
        self,
        query: str,
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        use_graph_context: bool = False
    ) -> List[SearchResult]:
        """
        Search for similar chunks.

        Args:
            query: Search query
            top_k: Number of results
            filters: Metadata filters
            use_graph_context: If using Neo4j, enrich results with graph context
        """
        # Generate query embedding
        query_embedding = await self._embedding_service.embed_text(query)

        # Search store
        if use_graph_context and isinstance(self._store, Neo4jStore):
            results = await self._store.search_with_graph_context(
                query_embedding,
                top_k=top_k,
                expand_techniques=True,
                expand_cves=True
            )
        else:
            results = await self._store.search(
                query_embedding,
                top_k=top_k,
                filters=filters
            )

        return results

    async def add_technique_relationship(self, chunk_id: str, technique_id: str):
        """Add MITRE technique relationship (Neo4j only)."""
        if isinstance(self._store, Neo4jStore):
            await self._store.add_technique_relationship(chunk_id, technique_id)
        else:
            logger.warning("Technique relationships only supported with Neo4j")

    async def add_cve_relationship(self, chunk_id: str, cve_id: str, severity: str = ""):
        """Add CVE relationship (Neo4j only)."""
        if isinstance(self._store, Neo4jStore):
            await self._store.add_cve_relationship(chunk_id, cve_id, severity)
        else:
            logger.warning("CVE relationships only supported with Neo4j")

    async def get_related_chunks(self, chunk_id: str, depth: int = 2) -> List[Chunk]:
        """Get related chunks through graph traversal (Neo4j only)."""
        if isinstance(self._store, Neo4jStore):
            return await self._store.get_related_chunks(chunk_id, depth)
        return []

    async def delete_documents(self, ids: List[str]):
        """Delete documents by ID."""
        await self._store.delete(ids)

    async def get_stats(self) -> Dict[str, Any]:
        """Get vector store statistics."""
        return await self._store.get_stats()

    async def close(self):
        """Close vector store connections."""
        if isinstance(self._store, Neo4jStore):
            await self._store.close()
