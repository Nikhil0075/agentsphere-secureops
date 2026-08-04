"""Build the hybrid retrieval index.

    python scripts/build_index.py                          # keyless TF-IDF/SVD embeddings
    python scripts/build_index.py --embeddings openai      # better vectors, needs OPENAI_API_KEY

Writes BM25, embeddings and corpus metadata to ``artifacts/index/``. Run once after
``prepare_data.py``; everything downstream loads from disk.

Building this ahead of time is what makes retrieval work with no network at query time: every
incident the system retrieves for is already in the corpus, so its embedding is a lookup.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import ARTIFACTS, ensure_dirs  # noqa: E402
from app.data import loader  # noqa: E402
from app.retrieval.hybrid import HybridRetriever  # noqa: E402

INDEX_DIR = ARTIFACTS / "index"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--embeddings",
        choices=["tfidf-svd", "openai"],
        default="tfidf-svd",
        help="embedding backend used at build time only",
    )
    parser.add_argument("--out", default=str(INDEX_DIR))
    parser.add_argument(
        "--sample", type=int, default=0, help="index only the first N incidents (for testing)"
    )
    args = parser.parse_args()

    ensure_dirs()
    _, incidents = loader.load_prepared()
    if args.sample:
        incidents = incidents.head(args.sample)

    print(f"indexing {len(incidents):,} incidents with {args.embeddings} embeddings ...")
    started = time.perf_counter()
    retriever = HybridRetriever.build(incidents, embedding_backend=args.embeddings)
    elapsed = time.perf_counter() - started

    out = Path(args.out)
    retriever.save(out)

    stats = {
        "incidents": len(incidents),
        "embedding_backend": args.embeddings,
        "dimensions": retriever.vectors.dimensions,
        "rrf_k": retriever.rrf_k,
        "candidate_depth": retriever.candidate_depth,
        "build_seconds": round(elapsed, 2),
    }
    (out / "index_stats.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8"
    )

    print(f"built in {elapsed:.1f}s -> {out}")
    print(f"  bm25 documents   {len(retriever.lexical):,}")
    print(f"  vectors          {len(retriever.vectors):,} x {retriever.vectors.dimensions}")

    # A quick sanity retrieval, so a broken index fails here rather than in the demo.
    probe = str(incidents["incident_id"].iloc[0])
    hits = retriever.similar(probe, k=3)
    print(f"\nprobe {probe} -> {len(hits)} hit(s)")
    for hit in hits:
        print(f"  {hit.incident_id}  {hit.score:.3f}  {hit.why()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
