"""Semantic retrieval: embeddings plus a FAISS index.

Two embedding backends behind one interface:

* ``openai`` — ``text-embedding-3-small``. Better quality, needs a key, costs about a cent for the
  whole corpus. Used at *build* time only.
* ``tfidf-svd`` — sklearn TF-IDF reduced by truncated SVD. No key, no network, no model download.
  Genuinely weaker, and said so plainly rather than dressed up as equivalent.

**Neither is called at query time.** Every incident this system retrieves for is already a member
of the corpus, so its vector is in the index — the query embedding is a lookup, not a computation.
That is what keeps the offline guarantee intact without a cache-warming step, and it is also why a
missing API key at demo time cannot break retrieval.

Index type is ``IndexFlatIP`` over L2-normalised vectors, which is exact cosine similarity by
construction (§8.1: normalise, then inner product). It is brute force. At 5,000 documents that is
the correct choice and an HNSW index would be a more complicated way to get a worse answer; §8.1
says to switch only when brute force is visibly slow, and it is not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from app.config import settings

OPENAI_EMBED_MODEL = "text-embedding-3-small"
OPENAI_BATCH = 256
TFIDF_DIMENSIONS = 384


class EmbeddingError(RuntimeError):
    pass


# --- embedding backends -----------------------------------------------------------------------

def embed_openai(texts: list[str], model: str = OPENAI_EMBED_MODEL) -> np.ndarray:
    if not settings.openai_api_key:
        raise EmbeddingError("OPENAI_API_KEY is not set; use --embeddings tfidf-svd instead")
    from openai import OpenAI

    client = OpenAI(api_key=settings.openai_api_key)
    vectors: list[list[float]] = []
    for start in range(0, len(texts), OPENAI_BATCH):
        batch = texts[start : start + OPENAI_BATCH]
        # The API rejects empty strings; a blank summary becomes a single space.
        batch = [t if t.strip() else " " for t in batch]
        response = client.embeddings.create(model=model, input=batch)
        vectors.extend(item.embedding for item in sorted(response.data, key=lambda d: d.index))
    return np.asarray(vectors, dtype=np.float32)


def embed_tfidf_svd(texts: list[str], dimensions: int = TFIDF_DIMENSIONS) -> np.ndarray:
    """Keyless fallback. Real vector space, weaker semantics — it cannot relate two summaries
    that share no vocabulary, which is precisely what a learned embedding is for."""
    from sklearn.decomposition import TruncatedSVD
    from sklearn.feature_extraction.text import TfidfVectorizer

    from app.retrieval.lexical import tokenize

    vectorizer = TfidfVectorizer(
        tokenizer=tokenize, lowercase=True, min_df=1, token_pattern=None
    )
    matrix = vectorizer.fit_transform(texts)
    # SVD cannot produce more components than the matrix has features or samples.
    components = min(dimensions, matrix.shape[1] - 1, matrix.shape[0] - 1)
    if components < 2:
        raise EmbeddingError(f"corpus too small to embed ({matrix.shape})")
    svd = TruncatedSVD(n_components=components, random_state=20260807)
    return svd.fit_transform(matrix).astype(np.float32)


def embed(texts: list[str], backend: str = "tfidf-svd") -> np.ndarray:
    if backend == "openai":
        return embed_openai(texts)
    if backend == "tfidf-svd":
        return embed_tfidf_svd(texts)
    raise EmbeddingError(f"unknown embedding backend {backend!r}")


def l2_normalise(vectors: np.ndarray) -> np.ndarray:
    """Unit-length rows, so inner product equals cosine similarity.

    A zero vector would divide by zero; its norm is forced to 1, leaving it as the zero vector,
    which then has similarity 0 with everything. That is the right answer for a document with no
    signal in it.
    """
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return (vectors / norms).astype(np.float32)


# --- the index ---------------------------------------------------------------------------------

@dataclass
class VectorIndex:
    incident_ids: list[str]
    vectors: np.ndarray           # L2-normalised, row i belongs to incident_ids[i]
    backend: str
    _faiss_index: object | None = None
    _position: dict[str, int] | None = None

    def __post_init__(self) -> None:
        self._position = {incident_id: i for i, incident_id in enumerate(self.incident_ids)}

    @classmethod
    def build(
        cls, incident_ids: list[str], summaries: list[str], backend: str = "tfidf-svd"
    ) -> "VectorIndex":
        if len(incident_ids) != len(summaries):
            raise ValueError("incident_ids and summaries must be the same length")
        vectors = l2_normalise(embed(summaries, backend=backend))
        return cls(incident_ids=list(incident_ids), vectors=vectors, backend=backend)

    def __len__(self) -> int:
        return len(self.incident_ids)

    @property
    def dimensions(self) -> int:
        return int(self.vectors.shape[1])

    def _index(self):
        """FAISS index, built lazily and cached. Falls back to numpy if FAISS is unavailable —
        the maths is identical, only the speed differs, and a missing wheel should not take the
        demo down."""
        if self._faiss_index is None:
            try:
                import faiss

                index = faiss.IndexFlatIP(self.dimensions)
                index.add(self.vectors)
                self._faiss_index = index
            except ImportError:
                self._faiss_index = False  # sentinel: use numpy
        return self._faiss_index

    def vector_for(self, incident_id: str) -> np.ndarray | None:
        position = self._position.get(incident_id)
        return None if position is None else self.vectors[position]

    def search(
        self, incident_id: str, k: int = 50, exclude_self: bool = True
    ) -> list[tuple[str, float]]:
        """Cosine-nearest incidents to one already in the corpus."""
        query = self.vector_for(incident_id)
        if query is None:
            return []
        return self.search_vector(
            query, k=k, exclude=incident_id if exclude_self else None
        )

    def search_vector(
        self, query: np.ndarray, k: int = 50, exclude: str | None = None
    ) -> list[tuple[str, float]]:
        query = np.asarray(query, dtype=np.float32).reshape(1, -1)
        # Ask for one extra so dropping the query itself still leaves k results.
        want = min(len(self.incident_ids), k + (1 if exclude else 0))
        if want <= 0:
            return []

        index = self._index()
        if index is False:
            scores = (self.vectors @ query.T).ravel()
            order = np.argpartition(-scores, min(want, len(scores) - 1))[:want]
            order = order[np.argsort(-scores[order])]
            hits = [(self.incident_ids[i], float(scores[i])) for i in order]
        else:
            scores, positions = index.search(query, want)
            hits = [
                (self.incident_ids[position], float(score))
                for position, score in zip(positions[0], scores[0])
                if position != -1
            ]

        return [(i, s) for i, s in hits if i != exclude][:k]

    # --- persistence -----------------------------------------------------------------

    def save(self, directory: str | Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        np.save(directory / "vectors.npy", self.vectors)
        (directory / "vectors_meta.json").write_text(
            json.dumps(
                {
                    "incident_ids": self.incident_ids,
                    "backend": self.backend,
                    "dimensions": self.dimensions,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, directory: str | Path) -> "VectorIndex":
        directory = Path(directory)
        meta = json.loads((directory / "vectors_meta.json").read_text(encoding="utf-8"))
        vectors = np.load(directory / "vectors.npy")
        return cls(
            incident_ids=meta["incident_ids"],
            vectors=vectors,
            backend=meta.get("backend", "unknown"),
        )
