"""Enron email corpus processor for ThreatSimGPT.

This processor handles the Enron email dataset to extract realistic
email communication patterns for enhanced phishing simulations.
"""

import logging
import asyncio
import tarfile
import gzip
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict, Counter

from ..base_processor import BaseDatasetProcessor
from ..manager import DatasetInfo, DatasetStatus, DatasetType, EmailPattern

logger = logging.getLogger(__name__)


@dataclass
class EmailMessage:
    """Represents an email message from the Enron corpus."""

    sender: str
    recipients: List[str]
    subject: str
    body: str
    date: Optional[datetime]
    folder: str
    message_id: str


class EnronProcessor(BaseDatasetProcessor):
    """Processor for Enron email corpus dataset."""

    def __init__(self, storage_path: Path):
        """Initialize Enron processor.

        Args:
            storage_path: Path to store Enron dataset
        """
        super().__init__(str(storage_path))

        # Dataset URLs and info
        self.dataset_url = "https://www.cs.cmu.edu/~./enron/enron_mail_20150507.tar.gz"
        self.dataset_file = self.storage_path / "enron_mail_20150507.tar.gz"
        self.extracted_path = self.storage_path / "maildir"

        # Processing cache
        self._patterns_cache: Dict[str, EmailPattern] = {}
        self._processed_data: Optional[Dict[str, Any]] = None

    async def get_dataset_info(self) -> DatasetInfo:
        """Get information about the Enron dataset."""
        status = DatasetStatus.NOT_DOWNLOADED
        version = "20150507"
        size_mb = None
        last_updated = None

        if self.dataset_file.exists():
            size_mb = self.dataset_file.stat().st_size / (1024 * 1024)
            last_updated = datetime.fromtimestamp(self.dataset_file.stat().st_mtime)

            if self.extracted_path.exists() and any(self.extracted_path.iterdir()):
                status = DatasetStatus.READY
            else:
                status = DatasetStatus.DOWNLOADED

        return DatasetInfo(
            name="Enron Email Corpus",
            type=DatasetType.ENRON,
            description="500,000+ emails from Enron executives for realistic email pattern analysis",
            source_url=self.dataset_url,
            version=version,
            size_mb=size_mb,
            last_updated=last_updated,
            status=status,
            features=[
                "email_style_patterns",
                "corporate_communication",
                "executive_language",
                "subject_line_analysis",
                "greeting_closing_patterns"
            ],
            use_cases=[
                "spear_phishing_templates",
                "corporate_email_simulation",
                "executive_impersonation",
                "business_email_compromise"
            ]
        )

    async def download_and_process(self, force: bool = False) -> bool:
        """Download and process the Enron dataset.

        Args:
            force: Force re-download even if exists

        Returns:
            True if successful, False otherwise
        """
        try:
            # Download if needed
            if force or not self.dataset_file.exists():
                logger.info("Downloading Enron email corpus...")
                success = await self.download_dataset()
                if not success:
                    return False

            # Extract if needed
            if force or not self.extracted_path.exists():
                logger.info("Extracting Enron email corpus...")
                success = await self._extract_dataset()
                if not success:
                    return False

            # Process emails for pattern extraction
            logger.info("Processing Enron emails for pattern extraction...")
            success = await self.process_dataset()
            if not success:
                return False

            logger.info("Enron dataset processing completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error processing Enron dataset: {e}")
            return False

    async def download_dataset(self) -> bool:
        """Download the Enron dataset (implements BaseDatasetProcessor abstract method)."""
        try:
            logger.info(f"Downloading from {self.dataset_url}")
            return await self.download_file(
                url=self.dataset_url,
                destination=self.dataset_file,
                progress_interval=10  # Log every 10MB
            )
        except Exception as e:
            logger.error(f"Error downloading Enron dataset: {e}")
            return False

    async def _extract_dataset(self) -> bool:
        """Extract the Enron dataset."""
        try:
            with tarfile.open(self.dataset_file, 'r:gz') as tar:
                tar.extractall(path=self.storage_path, filter='data')  # nosec B202

            logger.info("Enron dataset extraction completed")
            return True
        except Exception as e:
            logger.error(f"Error extracting Enron dataset: {e}")
            return False

    async def process_dataset(self) -> bool:
        """Process emails to extract patterns (implements BaseDatasetProcessor abstract method)."""
        try:
            if not self.extracted_path.exists():
                logger.error("Enron dataset not extracted")
                return False

            # Process emails in batches to avoid memory issues
            batch_size = 1000
            processed_count = 0

            # Data structures for pattern analysis
            subjects_by_role = defaultdict(list)
            greetings_by_role = defaultdict(list)
            closings_by_role = defaultdict(list)
            language_patterns = defaultdict(list)

            # Process user directories
            for user_dir in self.extracted_path.iterdir():
                if not user_dir.is_dir():
                    continue

                user_role = self._infer_user_role(user_dir.name)
                user_emails = await self._parse_user_emails(user_dir)

                for email in user_emails:
                    # Extract patterns
                    subjects_by_role[user_role].append(email.subject)

                    greeting = self._extract_greeting(email.body)
                    if greeting:
                        greetings_by_role[user_role].append(greeting)

                    closing = self._extract_closing(email.body)
                    if closing:
                        closings_by_role[user_role].append(closing)

                    # Extract language patterns
                    language_patterns[user_role].extend(
                        self._extract_language_patterns(email.body)
                    )

                    processed_count += 1

                    if processed_count % batch_size == 0:
                        logger.info(f"Processed {processed_count} emails")

            # Analyze and store patterns
            self._processed_data = {
                'subjects_by_role': dict(subjects_by_role),
                'greetings_by_role': dict(greetings_by_role),
                'closings_by_role': dict(closings_by_role),
                'language_patterns': dict(language_patterns),
                'processed_count': processed_count,
                'processed_date': datetime.utcnow().isoformat()
            }

            # Save processed data
            processed_file = self.storage_path / "processed_patterns.json"
            with open(processed_file, 'w') as f:
                json.dump(self._processed_data, f, indent=2)

            logger.info(f"Processed {processed_count} emails and extracted patterns")
            return True

        except Exception as e:
            logger.error(f"Error processing Enron emails: {e}")
            return False

    async def _parse_user_emails(self, user_dir: Path) -> List[EmailMessage]:
        """Parse emails for a specific user."""
        emails = []

        try:
            # Look for sent mail folder (most relevant for style analysis)
            sent_folder = user_dir / "sent"
            if sent_folder.exists():
                for email_file in sent_folder.glob("*."):
                    try:
                        email = await self._parse_email_file(email_file)
                        if email:
                            emails.append(email)
                    except Exception as e:
                        logger.debug(f"Error parsing email {email_file}: {e}")
                        continue

            # Limit per user to avoid memory issues
            return emails[:100]

        except Exception as e:
            logger.error(f"Error parsing user emails in {user_dir}: {e}")
            return []

    async def _parse_email_file(self, email_file: Path) -> Optional[EmailMessage]:
        """Parse a single email file."""
        try:
            with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Simple email parsing (could be enhanced with email library)
            lines = content.split('\n')

            sender = ""
            recipients = []
            subject = ""
            body_start = 0

            for i, line in enumerate(lines):
                if line.startswith('From: '):
                    sender = line[6:].strip()
                elif line.startswith('To: '):
                    recipients = [r.strip() for r in line[4:].split(',')]
                elif line.startswith('Subject: '):
                    subject = line[9:].strip()
                elif line.strip() == '':
                    body_start = i + 1
                    break

            body = '\n'.join(lines[body_start:])

            return EmailMessage(
                sender=sender,
                recipients=recipients,
                subject=subject,
                body=body,
                date=None,  # Could parse date if needed
                folder="sent",
                message_id=email_file.name
            )

        except Exception as e:
            logger.debug(f"Error parsing email file {email_file}: {e}")
            return None

    def _infer_user_role(self, username: str) -> str:
        """Infer user role from username."""
        # Simple heuristics - could be enhanced with actual role data
        executive_indicators = ['ceo', 'president', 'vp', 'chief', 'director']
        manager_indicators = ['manager', 'head', 'lead', 'supervisor']

        username_lower = username.lower()

        for indicator in executive_indicators:
            if indicator in username_lower:
                return 'executive'

        for indicator in manager_indicators:
            if indicator in username_lower:
                return 'manager'

        return 'employee'

    def _extract_greeting(self, body: str) -> Optional[str]:
        """Extract greeting from email body."""
        lines = body.split('\n')[:5]  # Check first 5 lines

        greeting_patterns = [
            r'^(Dear\s+\w+[,:])',
            r'^(Hi\s+\w+[,:])',
            r'^(Hello\s+\w+[,:])',
            r'^(Good\s+\w+\s+\w+[,:])',
            r'^(\w+[,:])'  # Simple name greeting
        ]

        for line in lines:
            line = line.strip()
            if not line:
                continue

            for pattern in greeting_patterns:
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1)

        return None

    def _extract_closing(self, body: str) -> Optional[str]:
        """Extract closing phrase from email body."""
        lines = body.split('\n')[-10:]  # Check last 10 lines

        closing_patterns = [
            r'^(Best\s+regards?[,.]?)',
            r'^(Sincerely[,.]?)',
            r'^(Thanks?[,.]?)',
            r'^(Thank\s+you[,.]?)',
            r'^(Regards?[,.]?)',
            r'^(Best[,.]?)'
        ]

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue

            for pattern in closing_patterns:
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1)

        return None

    def _extract_language_patterns(self, body: str) -> List[str]:
        """Extract common language patterns from email body."""
        patterns = []

        # Common business phrases
        business_phrases = [
            r'please\s+review',
            r'let\s+me\s+know',
            r'thanks?\s+for\s+your?\s+time',
            r'i\s+would\s+appreciate',
            r'at\s+your?\s+earliest\s+convenience',
            r'please\s+find\s+attached',
            r'looking\s+forward\s+to',
            r'please\s+let\s+me\s+know'
        ]

        body_lower = body.lower()
        for phrase_pattern in business_phrases:
            matches = re.findall(phrase_pattern, body_lower)
            patterns.extend(matches)

        return patterns

    async def extract_email_patterns(self, role: str = "general", industry: str = "energy") -> EmailPattern:
        """Extract email patterns for specific role and industry.

        Args:
            role: Target role (executive, manager, employee)
            industry: Target industry (defaults to energy for Enron)

        Returns:
            EmailPattern with extracted patterns
        """
        cache_key = f"{role}_{industry}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        # Load processed data if not in memory
        if not self._processed_data:
            processed_file = self.storage_path / "processed_patterns.json"
            if processed_file.exists():
                with open(processed_file, 'r') as f:
                    self._processed_data = json.load(f)
            else:
                logger.warning("No processed Enron data found")
                return self._get_default_patterns()

        try:
            # Get patterns for specific role
            role_subjects = self._processed_data.get('subjects_by_role', {}).get(role, [])
            role_greetings = self._processed_data.get('greetings_by_role', {}).get(role, [])
            role_closings = self._processed_data.get('closings_by_role', {}).get(role, [])
            role_language = self._processed_data.get('language_patterns', {}).get(role, [])

            # Analyze and extract top patterns
            subject_patterns = self._analyze_subject_patterns(role_subjects)
            greeting_styles = self._get_top_patterns(role_greetings, 5)
            closing_phrases = self._get_top_patterns(role_closings, 5)
            common_phrases = self._get_top_patterns(role_language, 10)

            pattern = EmailPattern(
                subject_patterns=subject_patterns,
                greeting_styles=greeting_styles,
                closing_phrases=closing_phrases,
                language_tone=self._determine_tone(role),
                formality_level=self._determine_formality(role),
                average_length=self._calculate_average_length(role_subjects + role_language),
                common_phrases=common_phrases
            )

            self._patterns_cache[cache_key] = pattern
            return pattern

        except Exception as e:
            logger.error(f"Error extracting email patterns: {e}")
            return self._get_default_patterns()

    def _analyze_subject_patterns(self, subjects: List[str]) -> List[str]:
        """Analyze subject line patterns."""
        if not subjects:
            return ["Re: {topic}", "FW: {topic}", "{topic} - Update"]

        # Extract common patterns
        patterns = []

        # Common prefixes
        re_count = sum(1 for s in subjects if s.lower().startswith('re:'))
        fw_count = sum(1 for s in subjects if s.lower().startswith('fw:'))

        if re_count > len(subjects) * 0.1:
            patterns.append("Re: {topic}")
        if fw_count > len(subjects) * 0.05:
            patterns.append("FW: {topic}")

        # Add generic patterns
        patterns.extend([
            "{topic} - Update",
            "{topic} - Action Required",
            "Meeting: {topic}",
            "{topic} - Please Review"
        ])

        return patterns[:5]

    def _get_top_patterns(self, items: List[str], count: int) -> List[str]:
        """Get top N most common patterns."""
        if not items:
            return []

        counter = Counter(items)
        return [item for item, _ in counter.most_common(count)]

    def _determine_tone(self, role: str) -> str:
        """Determine appropriate tone for role."""
        tone_map = {
            'executive': 'authoritative',
            'manager': 'professional',
            'employee': 'collaborative'
        }
        return tone_map.get(role, 'professional')

    def _determine_formality(self, role: str) -> str:
        """Determine formality level for role."""
        formality_map = {
            'executive': 'formal',
            'manager': 'business',
            'employee': 'casual'
        }
        return formality_map.get(role, 'business')

    def _calculate_average_length(self, texts: List[str]) -> int:
        """Calculate average text length."""
        if not texts:
            return 150

        total_length = sum(len(text) for text in texts)
        return total_length // len(texts)

    def _get_default_patterns(self) -> EmailPattern:
        """Get default email patterns when dataset is not available."""
        return EmailPattern(
            subject_patterns=["Re: {topic}", "FW: {topic}", "{topic} - Update"],
            greeting_styles=["Dear {name},", "Hi {name},", "Hello,"],
            closing_phrases=["Best regards,", "Thanks,", "Sincerely,"],
            language_tone="professional",
            formality_level="business",
            average_length=150,
            common_phrases=["Please review", "Let me know", "Thanks for your time"]
        )
    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the Enron dataset (implements BaseDatasetProcessor abstract method).

        Returns:
            Dict containing dataset statistics
        """
        stats = {
            'status': 'not_processed',
            'dataset_file': str(self.dataset_file),
            'extracted_path': str(self.extracted_path),
            'dataset_exists': self.dataset_file.exists(),
            'extracted_exists': self.extracted_path.exists(),
        }

        # Add file size if available
        if self.dataset_file.exists():
            stats['dataset_size_mb'] = self.get_file_size_mb(self.dataset_file)

        # Add processed data stats if available
        if self._processed_data:
            stats.update({
                'status': 'processed',
                'processed_count': self._processed_data.get('processed_count', 0),
                'processed_date': self._processed_data.get('processed_date'),
                'roles_analyzed': list(self._processed_data.get('subjects_by_role', {}).keys()),
                'patterns_cached': len(self._patterns_cache)
            })

        # Include base processor info
        stats['processor_info'] = self.get_processing_info()

        return stats
