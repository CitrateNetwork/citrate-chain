# examples/

Example scripts demonstrating AI model inference on the Citrate blockchain.

## inference/

Python scripts for model deployment and inference. Requires Python 3.9+,
`torch`, `transformers`, `web3`, and `ipfshttpclient`.

| Script | Description |
|--------|-------------|
| `text_classification.py` | Sentiment analysis using DistilBERT |
| `image_classification.py` | Image classification using ResNet-50 with top-k predictions |
| `batch_inference.py` | High-throughput batch processing with latency percentiles (P50/P95/P99) |

### Quick Start

```bash
pip install torch transformers web3 ipfshttpclient numpy pillow requests

# Start required services
ipfs daemon &
cargo run --release --bin citrate-node -- devnet &

# Run an example
python3 examples/inference/text_classification.py
python3 examples/inference/image_classification.py
python3 examples/inference/batch_inference.py
```

See `examples/inference/README.md` for detailed usage, model format options
(CoreML, MLX, ONNX), and benchmark results.
