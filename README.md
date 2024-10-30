# regexp-performance
Benchmark of different python regexp libraries on some edge cases

![Total for high percentiles](./alex-out/run_times_match_end.svg)

## How to run?

- Environment variable `RUNS` specifies number of runs for each call.
  - Recommended value is 11.
- Some libraries requires extra system libraries to be installed.
- I recommend podman/docker


### Podman/Docker
[Podman](https://podman.io/) allows to run container in rootless mode with no effort.
Docker commands will be similar.

```bash
podman build -t re-benchmark .
mkdir docker-out
podman run --rm  -v $(pwd)/docker-out:/app/graphs -e RUNS=11 re-benchmark  python measure_performance.py
```

Recommended variant because no dev libraries is needed.


### Pip/venv

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
RUNS=11 python measure_performance.py
```

Result images will be placed in `./graphs` directory.
