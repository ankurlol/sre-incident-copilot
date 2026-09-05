import re
import math
from typing import List, Dict, Any, Tuple
from rank_bm25 import BM25Okapi
from src.rag.indexer import KnowledgeIndexer, DocumentChunk

class HybridRetriever:
    def __init__(self, indexer: KnowledgeIndexer):
        self.indexer = indexer
        self.chunks = self.indexer.get_all_chunks()
        self._build_indexes()

    def _tokenize(self, text: str) -> List[str]:
        tokens = re.findall(r'[a-zA-Z0-9_\-]+', text.lower())
        return tokens

    def _build_indexes(self):
        self.chunks = self.indexer.get_all_chunks()
        if not self.chunks:
            self.bm25 = None
            return

        self.corpus_tokens = [self._tokenize(chunk.title + " " + chunk.content) for chunk in self.chunks]
        self.bm25 = BM25Okapi(self.corpus_tokens)

    def _compute_vector_score(self, query_tokens: List[str], doc_tokens: List[str]) -> float:
        # Cosine similarity on token term frequencies (sublinear TF-IDF style)
        if not query_tokens or not doc_tokens:
            return 0.0
        q_set = set(query_tokens)
        d_set = set(doc_tokens)
        intersection = q_set.intersection(d_set)
        if not intersection:
            return 0.0
        return len(intersection) / (math.sqrt(len(q_set)) * math.sqrt(len(d_set)))

    def search(self, query: str, top_k: int = 4, doc_type: str = None) -> List[Tuple[DocumentChunk, float]]:
        if not self.chunks or not self.bm25:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        # 1. BM25 Scores
        bm25_scores = self.bm25.get_scores(query_tokens)
        
        # 2. Vector / Semantic Scores
        vector_scores = [
            self._compute_vector_score(query_tokens, doc_toks) 
            for doc_toks in self.corpus_tokens
        ]

        # 3. Reciprocal Rank Fusion (RRF)
        # Sort indices by BM25
        bm25_ranked = sorted(range(len(self.chunks)), key=lambda i: bm25_scores[i], reverse=True)
        # Sort indices by Vector
        vector_ranked = sorted(range(len(self.chunks)), key=lambda i: vector_scores[i], reverse=True)

        k_constant = 60.0
        rrf_scores: Dict[int, float] = {}

        for rank, idx in enumerate(bm25_ranked):
            if bm25_scores[idx] > 0:
                rrf_scores[idx] = rrf_scores.get(idx, 0.0) + (1.0 / (k_constant + rank + 1))

        for rank, idx in enumerate(vector_ranked):
            if vector_scores[idx] > 0:
                rrf_scores[idx] = rrf_scores.get(idx, 0.0) + (1.0 / (k_constant + rank + 1))

        # Filter by doc_type if requested
        ranked_results = []
        for idx in sorted(rrf_scores.keys(), key=lambda i: rrf_scores[i], reverse=True):
            chunk = self.chunks[idx]
            if doc_type and chunk.doc_type != doc_type:
                continue
            normalized_score = min(1.0, rrf_scores[idx] * 35.0) # Scaled for UI display
            ranked_results.append((chunk, round(normalized_score, 3)))
            if len(ranked_results) >= top_k:
                break

        return ranked_results
