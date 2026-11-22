# Local Vector Database Latency and Recall Benchmark (2026)

We evaluated Qdrant, pgvector, and LanceDB on 1 million 768-dimensional float32 vectors using a single NVMe node.

## Findings
- Qdrant achieved strong p95 query latency under concurrent reads, though memory usage rises noticeably without scalar quantization.
- pgvector offers operational simplicity inside existing PostgreSQL clusters; however, HNSW index build time and RAM overhead remain clear drawbacks on 8GB instances.
- LanceDB minimizes idle memory footprint via disk-backed IVF-PQ, on the other hand cold-start tail latency is a caveat for interactive workloads.

## Limitations
All measurements depend heavily on batch size, quantization parameters, and OS page cache warmth. This benchmark is not sponsored and includes no affiliate links.
