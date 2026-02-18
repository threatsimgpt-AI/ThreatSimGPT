# FalkorDB Setup Guide for ThreatSimGPT RAG System

This guide will help you set up FalkorDB as the primary vector store
for the ThreatSimGPT RAG system with MITRE ATT&CK integration.

## 🎯 **Prerequisites**

### Required Software
- **Neo4j Database** (5.0+ recommended)
- **Python Neo4j Driver** (`neo4j`)
- **Docker** (recommended for containerized setup)
- **Python Dependencies**:
  ```bash
  pip install neo4j
  pip install python-dotenv
  ```

### System Requirements
- **Memory**: Minimum 4GB RAM recommended
- **Storage**: Minimum 10GB free space
- **Network**: Stable connection to Neo4j instance

## 🚀 **Setup Instructions**

### 1. **Environment Configuration**

Create `.env` file in your project root:

```bash
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_password_here
NEO4J_DATABASE=neo4j

# RAG System Configuration
VECTORSTORE_TYPE=neo4j
VECTORSTORE_HOST=localhost
VECTORSTORE_PORT=7687
VECTORSTORE_COLLECTION_NAME=threatsimgpt_intelligence
```

### 2. **Neo4j Database Setup**

#### Option A: Docker Setup (Recommended)
```bash
# Pull Neo4j Docker image
docker pull neo4j:5.15

# Run Neo4j container
docker run \
  --name neo4j \
  -p 7474:7687:7687 \
  -p 7687:7688 \
  -e NEO4J_AUTH=neo4j/your_password_here \
  -e NEO4J_PLUGINS=["apoc"] \
  -e NEO4J_dbms.security.auth.enabled=true \
  -v $(pwd)/data:/data \
  neo4j
```

#### Option B: Local Installation
```bash
# Download and install Neo4j
# Visit: https://neo4j.com/download/
# Follow installation instructions for your OS

# Start Neo4j service
# On macOS: brew services start neo4j
# On Linux: sudo systemctl start neo4j
# On Windows: neo4j console
```

### 3. **Database Schema Setup**

The refactored VectorStoreManager will automatically create the required schema:

```cypher
// Create constraints for unique IDs
CREATE CONSTRAINT chunk_id IF NOT EXISTS FOR (c:Chunk) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT document_id IF NOT EXISTS FOR (d:Document) REQUIRE d.id IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (v:CVE) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT threat_actor_id IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.id IS UNIQUE;

// Create indexes for vector search
CREATE VECTOR INDEX chunk_embeddings IF NOT EXISTS
FOR (c:Chunk) ON (c.embedding)
OPTIONS {
  indexConfig: {
    `vector.dimensions`: $dimensions,
    `vector.similarity_function`: $similarity
  }
};

// Create full-text search index
CREATE FULLTEXT INDEX chunk_content IF NOT EXISTS
FOR (c:Chunk) ON (c.content);

// Create relationship indexes
CREATE INDEX chunk_source_url IF NOT EXISTS FOR (c:Chunk) ON (c.source_url);
CREATE INDEX chunk_created_at IF NOT EXISTS FOR (c:Chunk) ON (c.created_at);
```

### 4. **Integration with RAG System**

Update your VectorStoreConfig to use Neo4j:

```python
from threatsimgpt.rag.config import VectorStoreConfig, VectorStoreType

config = VectorStoreConfig(
    store_type=VectorStoreType.NEO4J,
    host="localhost",
    port=7687,
    collection_name="threatsimgpt_intelligence",
    hybrid_store_types=[],  # Add other stores if needed
    use_graph_context=True,
    database="neo4j"
)
```

### 5. **Testing the Setup**

#### Test Connection
```python
import asyncio
from threatsimgpt.rag.refactored_vectorstore import HybridVectorStoreManager
from threatsimgpt.rag.config import VectorStoreConfig

async def test_neo4j():
    config = VectorStoreConfig(
        store_type=VectorStoreType.NEO4J,
        host="localhost",
        port=7687,
        database="neo4j"
    )
    
    manager = HybridVectorStoreManager(config)
    await manager.initialize()
    
    # Test basic functionality
    results = await manager.search("test query", top_k=5)
    print(f"Found {len(results)} results")
    
    await manager.close()

if __name__ == "__main__":
    asyncio.run(test_neo4j())
```

### 6. **Environment Variables**

```bash
# For production
export NEO4J_URI=bolt://your-neo4j-host:7687
export NEO4J_USERNAME=neo4j
export NEO4J_PASSWORD=your_secure_password
export NEO4J_DATABASE=neo4j

# For development
export NEO4J_URI=bolt://localhost:7687
```

### 7. **Performance Optimization**

#### Vector Index Configuration
- **Dimensions**: Use 1536 for OpenAI embeddings
- **Similarity**: Cosine similarity for semantic search
- **Batch Size**: 100 vectors per batch for optimal performance
- **Memory Mapping**: Configure Neo4j memory settings for large datasets

#### Caching Strategy
- Enable query result caching in HybridVectorStoreManager
- Set appropriate TTL based on your data freshness requirements
- Consider using Redis for distributed caching in production

### 8. **Security Considerations**

```bash
# Secure Neo4j connection
NEO4J_ENCRYPTION=false  # Enable if required
NEO4J_TRUST_ALL_CERTIFICATES=false  # For development only

# Use environment variables for credentials
# Never hard-code passwords in configuration files
```

### 9. **Troubleshooting**

#### Common Issues
1. **Connection Refused**: Check Neo4j is running and accessible
2. **Authentication Failed**: Verify username/password and database name
3. **Index Creation Failed**: Check user permissions and available memory
4. **Slow Performance**: Monitor vector index size and query complexity

#### Debug Commands
```bash
# Check Neo4j status
curl -u neo4j:your_password -X POST http://localhost:7474/db/data/

# Test vector search
curl -X POST -H "Content-Type: application/json" \
  -d '{
    "query": "test search",
    "top_k": 5
  "filters": {"source_url": "example.com"}
  }' \
  http://localhost:7474/db/neo4j/
```

## 🎯 **Next Steps**

1. **Set up Neo4j** using Option A or B above
2. **Update environment variables** in your `.env` file
3. **Test the connection** with the provided test script
4. **Configure HybridVectorStoreManager** to use Neo4j as primary store
5. **Run your RAG system** and monitor performance

## 📞 **Resources**

- **Neo4j Documentation**: https://neo4j.com/docs/
- **Python Driver Docs**: https://neo4j.com/docs/python-manual/current/
- **Cypher Reference**: https://neo4j.com/docs/cypher-refcard/
- **Vector Index Documentation**: https://neo4j.com/docs/cypher-manual/current/vector-indexes/

## 🔧 **Configuration Examples**

### Development Configuration
```python
# dev.py
from threatsimgpt.rag.config import VectorStoreConfig, VectorStoreType

config = VectorStoreConfig(
    store_type=VectorStoreType.NEO4J,
    host="localhost",
    port=7687,
    database="neo4j",
    use_graph_context=True,
    hybrid_store_types=[VectorStoreType.CHROMADB],  # Add fallback stores
    hybrid_store_weights={
        "neo4j": 1.0,
        "chromadb": 0.7,
        "faiss": 0.5
    }
)
```

### Production Configuration
```python
# prod.py
import os
from threatsimgpt.rag.config import VectorStoreConfig, VectorStoreType

config = VectorStoreConfig(
    store_type=VectorStoreType.NEO4J,
    host=os.environ.get("NEO4J_URI", "bolt://prod-neo4j:7687"),
    port=int(os.environ.get("NEO4J_PORT", "7687")),
    database=os.environ.get("NEO4J_DATABASE", "neo4j"),
    username=os.environ.get("NEO4J_USERNAME", "neo4j"),
    password=os.environ.get("NEO4J_PASSWORD"),
    collection_name="threatsimgpt_intelligence",
    use_graph_context=True,
    hybrid_store_types=[VectorStoreType.CHROMADB],  # Production fallback
    hybrid_store_weights={
        "neo4j": 1.0,
        "chromadb": 0.7,
        "faiss": 0.5
    }
)
```

---

**🎯 Your RAG system is now ready for production with FalkorDB!**

The HybridVectorStoreManager will automatically handle:
- Schema creation and management
- Vector index creation and optimization
- Graph-enhanced search with MITRE ATT&CK integration
- Performance monitoring and caching
- Graceful fallbacks and error handling

Follow this guide and you'll have a robust, production-ready vector store! 🚀
