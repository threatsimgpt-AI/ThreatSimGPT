"""
RAG Intelligence Ingester
=========================

Multi-source intelligence ingestion system that fetches, parses,
and processes content from trusted cybersecurity sources.
"""

import asyncio
import hashlib
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Type
from dataclasses import dataclass, field
import json
import logging

import aiohttp
from bs4 import BeautifulSoup

from .models import Document, SourceType, ThreatCategory, Sector
from .config import SourceConfig, ChunkingConfig

logger = logging.getLogger(__name__)


# ==========================================
# Base Source Crawler
# ==========================================

class SourceCrawler(ABC):
    """Base class for intelligence source crawlers."""

    def __init__(self, config: SourceConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self._last_fetch: Optional[datetime] = None
        self._fetch_count = 0

    @abstractmethod
    async def fetch_documents(self) -> AsyncGenerator[Document, None]:
        """Fetch documents from the source."""
        pass

    @abstractmethod
    def parse_document(self, raw_data: Any) -> Optional[Document]:
        """Parse raw data into a Document."""
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        headers = {
            "User-Agent": "ThreatSimGPT-Intelligence/1.0",
            **self.config.headers
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def fetch_json(self, url: str) -> Dict[str, Any]:
        """Fetch JSON from URL."""
        async with self.session.get(url) as response:
            response.raise_for_status()
            return await response.json()

    async def fetch_html(self, url: str) -> str:
        """Fetch HTML from URL."""
        async with self.session.get(url) as response:
            response.raise_for_status()
            return await response.text()

    async def fetch_rss(self, url: str) -> str:
        """Fetch RSS/XML from URL."""
        async with self.session.get(url) as response:
            response.raise_for_status()
            return await response.text()

    def should_fetch(self) -> bool:
        """Check if enough time has passed since last fetch."""
        if not self._last_fetch:
            return True

        delta = datetime.utcnow() - self._last_fetch
        return delta > timedelta(hours=self.config.fetch_interval_hours)

    def _generate_doc_id(self, url: str, title: str) -> str:
        """Generate unique document ID."""
        content = f"{url}{title}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# ==========================================
# NIST NVD Crawler
# ==========================================

class NISTNVDCrawler(SourceCrawler):
    """Crawler for NIST National Vulnerability Database."""

    async def fetch_documents(self) -> AsyncGenerator[Document, None]:
        """Fetch CVE documents from NVD."""
        if not self.should_fetch():
            return

        self._last_fetch = datetime.utcnow()

        # Fetch recent CVEs
        params = {
            "resultsPerPage": min(self.config.max_documents_per_fetch, 2000),
            "lastModStartDate": (datetime.utcnow() - timedelta(days=7)).isoformat(),
        }

        url = self.config.base_url
        if self.config.api_key:
            url += f"?apiKey={self.config.api_key}"

        try:
            data = await self.fetch_json(url)

            for vuln in data.get("vulnerabilities", []):
                doc = self.parse_document(vuln)
                if doc:
                    yield doc
                    self._fetch_count += 1

                    if self._fetch_count >= self.config.max_documents_per_fetch:
                        break

        except Exception as e:
            logger.error(f"Error fetching from NIST NVD: {e}")

    def parse_document(self, raw_data: Dict[str, Any]) -> Optional[Document]:
        """Parse NVD CVE into Document."""
        try:
            cve = raw_data.get("cve", {})
            cve_id = cve.get("id", "")

            # Extract descriptions
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                ""
            )

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
            cvss_data = cvss_v31.get("cvssData", {})

            # Determine severity
            base_score = cvss_data.get("baseScore", 0)
            if base_score >= 9.0:
                severity = "critical"
            elif base_score >= 7.0:
                severity = "high"
            elif base_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"

            # Extract references
            references = cve.get("references", [])

            # Build content
            content = f"""# {cve_id}

## Description
{description}

## CVSS Score
Base Score: {base_score}
Severity: {severity.upper()}
Vector: {cvss_data.get("vectorString", "N/A")}

## References
""" + "\n".join(f"- {ref.get('url', '')}" for ref in references[:10])

            # Extract CWEs
            weaknesses = cve.get("weaknesses", [])
            cwes = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwes.append(desc.get("value", ""))

            return Document(
                id=f"nvd_{cve_id}",
                source_type=SourceType.NIST_NVD,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                title=cve_id,
                content=content,
                published_date=datetime.fromisoformat(
                    cve.get("published", datetime.utcnow().isoformat()).replace("Z", "+00:00")
                ).replace(tzinfo=None),
                cve_ids=[cve_id],
                categories=cwes,
                tags=[severity, "vulnerability", "cve"],
                reliability_score=self.config.reliability_score,
                raw_metadata={
                    "cvss_score": base_score,
                    "cvss_vector": cvss_data.get("vectorString"),
                    "cwes": cwes,
                }
            )

        except Exception as e:
            logger.error(f"Error parsing NVD CVE: {e}")
            return None


# ==========================================
# MITRE ATT&CK Crawler
# ==========================================

class MITREAttackCrawler(SourceCrawler):
    """Crawler for MITRE ATT&CK Framework."""

    async def fetch_documents(self) -> AsyncGenerator[Document, None]:
        """Fetch technique documents from MITRE ATT&CK."""
        if not self.should_fetch():
            return

        self._last_fetch = datetime.utcnow()

        try:
            data = await self.fetch_json(self.config.base_url)

            objects = data.get("objects", [])

            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    doc = self.parse_document(obj)
                    if doc:
                        yield doc
                        self._fetch_count += 1

        except Exception as e:
            logger.error(f"Error fetching from MITRE ATT&CK: {e}")

    def parse_document(self, raw_data: Dict[str, Any]) -> Optional[Document]:
        """Parse MITRE ATT&CK technique into Document."""
        try:
            # Extract external references
            ext_refs = raw_data.get("external_references", [])
            mitre_ref = next(
                (r for r in ext_refs if r.get("source_name") == "mitre-attack"),
                {}
            )
            technique_id = mitre_ref.get("external_id", "")
            url = mitre_ref.get("url", "")

            name = raw_data.get("name", "")
            description = raw_data.get("description", "")

            # Extract kill chain phases
            kill_chain = raw_data.get("kill_chain_phases", [])
            phases = [kc.get("phase_name", "") for kc in kill_chain]

            # Extract platforms
            platforms = raw_data.get("x_mitre_platforms", [])

            # Extract detection
            detection = raw_data.get("x_mitre_detection", "")

            # Build content
            content = f"""# {technique_id}: {name}

## Description
{description}

## Kill Chain Phases
{", ".join(phases)}

## Platforms
{", ".join(platforms)}

## Detection
{detection}
"""

            return Document(
                id=f"mitre_{technique_id}",
                source_type=SourceType.MITRE_ATTACK,
                source_url=url,
                title=f"{technique_id}: {name}",
                content=content,
                categories=phases,
                tags=platforms + ["mitre", "attack-pattern"],
                mitre_techniques=[technique_id],
                reliability_score=self.config.reliability_score,
                raw_metadata={
                    "technique_id": technique_id,
                    "kill_chain_phases": phases,
                    "platforms": platforms,
                }
            )

        except Exception as e:
            logger.error(f"Error parsing MITRE technique: {e}")
            return None


# ==========================================
# CISA Crawler
# ==========================================

class CISACrawler(SourceCrawler):
    """Crawler for CISA Known Exploited Vulnerabilities."""

    async def fetch_documents(self) -> AsyncGenerator[Document, None]:
        """Fetch KEV documents from CISA."""
        if not self.should_fetch():
            return

        self._last_fetch = datetime.utcnow()

        try:
            data = await self.fetch_json(self.config.base_url)

            vulnerabilities = data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                doc = self.parse_document(vuln)
                if doc:
                    yield doc
                    self._fetch_count += 1

                    if self._fetch_count >= self.config.max_documents_per_fetch:
                        break

        except Exception as e:
            logger.error(f"Error fetching from CISA: {e}")

    def parse_document(self, raw_data: Dict[str, Any]) -> Optional[Document]:
        """Parse CISA KEV into Document."""
        try:
            cve_id = raw_data.get("cveID", "")
            vendor = raw_data.get("vendorProject", "")
            product = raw_data.get("product", "")
            vuln_name = raw_data.get("vulnerabilityName", "")
            description = raw_data.get("shortDescription", "")
            action = raw_data.get("requiredAction", "")
            due_date = raw_data.get("dueDate", "")

            content = f"""# {cve_id}: {vuln_name}

## Affected Product
**Vendor:** {vendor}
**Product:** {product}

## Description
{description}

## Required Action
{action}

## Due Date for Remediation
{due_date}

## Notes
{raw_data.get("notes", "")}
"""

            return Document(
                id=f"cisa_{cve_id}",
                source_type=SourceType.CISA_ADVISORY,
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                title=f"{cve_id}: {vuln_name}",
                content=content,
                cve_ids=[cve_id],
                tags=["kev", "exploited", "cisa", vendor.lower()],
                reliability_score=self.config.reliability_score,
                raw_metadata=raw_data,
            )

        except Exception as e:
            logger.error(f"Error parsing CISA KEV: {e}")
            return None


# ==========================================
# RSS Feed Crawler
# ==========================================

class RSSFeedCrawler(SourceCrawler):
    """Crawler for RSS/Atom feeds (SecurityWeek, Krebs, etc.)."""

    async def fetch_documents(self) -> AsyncGenerator[Document, None]:
        """Fetch articles from RSS feed."""
        if not self.should_fetch():
            return

        self._last_fetch = datetime.utcnow()

        try:
            xml_content = await self.fetch_rss(self.config.base_url)
            soup = BeautifulSoup(xml_content, "xml")

            items = soup.find_all("item") or soup.find_all("entry")

            for item in items:
                doc = self.parse_document(item)
                if doc:
                    yield doc
                    self._fetch_count += 1

                    if self._fetch_count >= self.config.max_documents_per_fetch:
                        break

        except Exception as e:
            logger.error(f"Error fetching RSS feed: {e}")

    def parse_document(self, raw_data: BeautifulSoup) -> Optional[Document]:
        """Parse RSS item into Document."""
        try:
            title = raw_data.find("title")
            title_text = title.get_text(strip=True) if title else "Untitled"

            link = raw_data.find("link")
            link_text = link.get_text(strip=True) if link else link.get("href", "") if link else ""

            description = raw_data.find("description") or raw_data.find("summary")
            desc_text = description.get_text(strip=True) if description else ""

            # Try to get full content
            content_elem = raw_data.find("content:encoded") or raw_data.find("content")
            if content_elem:
                # Parse HTML content
                content_soup = BeautifulSoup(content_elem.get_text(), "html.parser")
                content_text = content_soup.get_text(separator="\n", strip=True)
            else:
                content_text = desc_text

            # Get published date
            pub_date = raw_data.find("pubDate") or raw_data.find("published")
            pub_date_text = pub_date.get_text(strip=True) if pub_date else None

            # Parse date
            published = None
            if pub_date_text:
                try:
                    from email.utils import parsedate_to_datetime
                    published = parsedate_to_datetime(pub_date_text).replace(tzinfo=None)
                except Exception:
                    pass

            # Extract CVE IDs from content
            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
            cve_ids = list(set(cve_pattern.findall(content_text)))

            # Build full content
            full_content = f"""# {title_text}

{content_text}
"""

            return Document(
                id=self._generate_doc_id(link_text, title_text),
                source_type=SourceType.SECURITY_BLOG,
                source_url=link_text,
                title=title_text,
                content=full_content,
                published_date=published,
                cve_ids=cve_ids,
                tags=["news", "security", self.config.name.lower().replace(" ", "_")],
                reliability_score=self.config.reliability_score,
            )

        except Exception as e:
            logger.error(f"Error parsing RSS item: {e}")
            return None


# ==========================================
# Intelligence Ingester
# ==========================================

# Crawler registry
CRAWLER_REGISTRY: Dict[str, Type[SourceCrawler]] = {
    "nist_nvd": NISTNVDCrawler,
    "mitre_attack": MITREAttackCrawler,
    "cisa_advisory": CISACrawler,
    "security_blog": RSSFeedCrawler,
    "threat_feed": RSSFeedCrawler,  # Default to RSS for feeds
}


class IntelligenceIngester:
    """
    Multi-source intelligence ingester.

    Orchestrates fetching from multiple sources and processes
    documents into the vector store.
    """

    def __init__(
        self,
        sources: List[SourceConfig],
        output_dir: Optional[Path] = None
    ):
        self.sources = sources
        self.output_dir = output_dir or Path("./data/raw")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._stats = {
            "total_documents": 0,
            "by_source": {},
            "errors": [],
        }

    def get_crawler(self, config: SourceConfig) -> Optional[SourceCrawler]:
        """Get appropriate crawler for source type."""
        crawler_class = CRAWLER_REGISTRY.get(config.source_type)
        if crawler_class:
            return crawler_class(config)
        logger.warning(f"No crawler for source type: {config.source_type}")
        return None

    async def ingest_all(self) -> List[Document]:
        """Ingest documents from all enabled sources."""
        all_documents = []

        tasks = []
        for source in self.sources:
            if source.enabled:
                tasks.append(self._ingest_source(source))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self._stats["errors"].append(str(result))
            elif isinstance(result, list):
                all_documents.extend(result)

        self._stats["total_documents"] = len(all_documents)

        return all_documents

    async def _ingest_source(self, config: SourceConfig) -> List[Document]:
        """Ingest documents from a single source."""
        documents = []

        crawler = self.get_crawler(config)
        if not crawler:
            return documents

        try:
            async with crawler:
                async for doc in crawler.fetch_documents():
                    documents.append(doc)

                    # Save raw document
                    self._save_document(doc)

            self._stats["by_source"][config.name] = len(documents)
            logger.info(f"Ingested {len(documents)} documents from {config.name}")

        except Exception as e:
            logger.error(f"Error ingesting from {config.name}: {e}")
            self._stats["errors"].append(f"{config.name}: {str(e)}")

        return documents

    def _save_document(self, doc: Document):
        """Save document to disk."""
        source_dir = self.output_dir / doc.source_type.value
        source_dir.mkdir(exist_ok=True)

        filepath = source_dir / f"{doc.id}.json"
        with open(filepath, 'w') as f:
            json.dump(doc.to_dict(), f, indent=2, default=str)

    def get_stats(self) -> Dict[str, Any]:
        """Get ingestion statistics."""
        return self._stats

    async def ingest_source(self, source_name: str) -> List[Document]:
        """Ingest from a specific source by name."""
        for source in self.sources:
            if source.name == source_name and source.enabled:
                return await self._ingest_source(source)
        return []


# ==========================================
# Text Chunker
# ==========================================

@dataclass
class TextChunker:
    """Intelligent text chunker for document processing."""

    config: ChunkingConfig = field(default_factory=ChunkingConfig)

    def chunk_document(self, doc: Document) -> List[Dict[str, Any]]:
        """Chunk a document into smaller pieces."""
        from .models import Chunk

        text = doc.content
        chunks = []

        if self.config.strategy.value == "recursive":
            raw_chunks = self._recursive_split(text)
        elif self.config.strategy.value == "sentence":
            raw_chunks = self._sentence_split(text)
        else:
            raw_chunks = self._fixed_size_split(text)

        for i, (content, start, end) in enumerate(raw_chunks):
            chunk = Chunk(
                id=f"{doc.id}_chunk_{i}",
                document_id=doc.id,
                content=content,
                chunk_index=i,
                start_char=start,
                end_char=end,
                source_type=doc.source_type,
                source_url=doc.source_url,
                document_title=doc.title,
            )
            chunks.append(chunk.to_dict())

        return chunks

    def _recursive_split(self, text: str) -> List[tuple]:
        """Recursively split text using separators."""
        chunks = []

        def split_recursive(text: str, separators: List[str], start_offset: int = 0):
            if len(text) <= self.config.chunk_size:
                if len(text) >= self.config.min_chunk_size:
                    chunks.append((text, start_offset, start_offset + len(text)))
                return

            if not separators:
                # Fall back to fixed size
                for i in range(0, len(text), self.config.chunk_size - self.config.chunk_overlap):
                    end = min(i + self.config.chunk_size, len(text))
                    chunk = text[i:end]
                    if len(chunk) >= self.config.min_chunk_size:
                        chunks.append((chunk, start_offset + i, start_offset + end))
                return

            sep = separators[0]
            parts = text.split(sep)

            current_chunk = ""
            current_start = start_offset

            for part in parts:
                if len(current_chunk) + len(part) + len(sep) <= self.config.chunk_size:
                    current_chunk += part + sep
                else:
                    if current_chunk:
                        if len(current_chunk) >= self.config.min_chunk_size:
                            chunks.append((
                                current_chunk.strip(),
                                current_start,
                                current_start + len(current_chunk)
                            ))
                        current_start += len(current_chunk)

                    if len(part) > self.config.chunk_size:
                        split_recursive(part, separators[1:], current_start)
                        current_start += len(part) + len(sep)
                        current_chunk = ""
                    else:
                        current_chunk = part + sep

            if current_chunk and len(current_chunk.strip()) >= self.config.min_chunk_size:
                chunks.append((
                    current_chunk.strip(),
                    current_start,
                    current_start + len(current_chunk)
                ))

        split_recursive(text, self.config.separators)
        return chunks

    def _sentence_split(self, text: str) -> List[tuple]:
        """Split text by sentences."""
        import re

        sentence_endings = re.compile(r'(?<=[.!?])\s+')
        sentences = sentence_endings.split(text)

        chunks = []
        current_chunk = ""
        current_start = 0
        char_pos = 0

        for sentence in sentences:
            if len(current_chunk) + len(sentence) <= self.config.chunk_size:
                if not current_chunk:
                    current_start = char_pos
                current_chunk += sentence + " "
            else:
                if current_chunk:
                    chunks.append((
                        current_chunk.strip(),
                        current_start,
                        current_start + len(current_chunk)
                    ))
                current_chunk = sentence + " "
                current_start = char_pos

            char_pos += len(sentence) + 1

        if current_chunk:
            chunks.append((
                current_chunk.strip(),
                current_start,
                current_start + len(current_chunk)
            ))

        return chunks

    def _fixed_size_split(self, text: str) -> List[tuple]:
        """Split text into fixed-size chunks with overlap."""
        chunks = []

        step = self.config.chunk_size - self.config.chunk_overlap

        for i in range(0, len(text), step):
            end = min(i + self.config.chunk_size, len(text))
            chunk = text[i:end]

            if len(chunk) >= self.config.min_chunk_size:
                chunks.append((chunk, i, end))

        return chunks
