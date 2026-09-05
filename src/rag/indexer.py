import os
import re
import glob
from typing import List, Dict, Any
from pydantic import BaseModel

class DocumentChunk(BaseModel):
    id: str
    source_file: str
    doc_type: str # 'runbook' or 'post_mortem'
    title: str
    content: str
    metadata: Dict[str, Any] = {}

class KnowledgeIndexer:
    def __init__(self, runbooks_dir: str = 'data/runbooks', post_mortems_dir: str = 'data/post_mortems'):
        self.runbooks_dir = runbooks_dir
        self.post_mortems_dir = post_mortems_dir
        self.chunks: List[DocumentChunk] = []
        self._load_documents()

    def _extract_title(self, content: str, default: str) -> str:
        match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return default

    def _extract_keywords(self, content: str) -> List[str]:
        match = re.search(r'Keywords:\s*(.+)$', content, re.MULTILINE | re.IGNORECASE)
        if match:
            return [k.strip().lower() for k in match.group(1).split(',') if k.strip()]
        return []

    def _chunk_markdown(self, filepath: str, doc_type: str) -> List[DocumentChunk]:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        filename = os.path.basename(filepath)
        main_title = self._extract_title(content, filename)
        keywords = self._extract_keywords(content)

        # Split by secondary headers (##) or keep as semantic sections
        sections = re.split(r'\n(?=##\s+)', content)
        chunks = []

        for idx, section in enumerate(sections):
            section_title = self._extract_title(section, f"{main_title} Part {idx+1}")
            chunk_id = f"{filename}#section-{idx+1}"
            chunks.append(DocumentChunk(
                id=chunk_id,
                source_file=filename,
                doc_type=doc_type,
                title=f"{main_title} - {section_title}" if section_title != main_title else main_title,
                content=section.strip(),
                metadata={
                    "keywords": keywords,
                    "filepath": filepath,
                    "doc_type": doc_type
                }
            ))
        return chunks

    def _load_documents(self):
        self.chunks = []
        # Load runbooks
        for filepath in glob.glob(os.path.join(self.runbooks_dir, "*.md")):
            self.chunks.extend(self._chunk_markdown(filepath, "runbook"))

        # Load post-mortems
        for filepath in glob.glob(os.path.join(self.post_mortems_dir, "*.md")):
            self.chunks.extend(self._chunk_markdown(filepath, "post_mortem"))

    def get_all_chunks(self) -> List[DocumentChunk]:
        if not self.chunks:
            self._load_documents()
        return self.chunks

    def reload(self):
        self._load_documents()
