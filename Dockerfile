# FortiCheck — FortiGate configuration security analyzer
#
# Run with current directory mounted so config and output use your local files:
#   docker run --rm -v "$(pwd):/workspace" forticheck:latest analyze -c sample.conf -o /workspace/report.html

FROM python:3.12-slim

LABEL maintainer="Cuma KURT <cumakurt@gmail.com>"
LABEL description="FortiCheck - FortiGate firewall configuration security analysis"

# Avoid writing bytecode and set unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

# Install package and dependencies
COPY pyproject.toml .
COPY forticheck/ forticheck/
COPY README.md LICENSE ./

RUN pip install --no-cache-dir .

# Default: run forticheck; override with full command (e.g. forticheck analyze -c ...)
ENTRYPOINT ["forticheck"]
CMD ["--help"]
