# One image, four commands:
#   uvicorn registry.api:app --host 0.0.0.0 --port 8080   the registry API
#   python -m registry.publisher                          files policy commits as changes, publishes approved changes
#   python -m registry.gitexport                          daily export of the records to Git
#   python -m registry.importer --owner-group G           first load from projects/*.yaml
FROM openpolicyagent/opa:1.22.2-static AS opa

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=opa /opa /usr/local/bin/opa
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY registry /app/registry
WORKDIR /app
ENV HOME=/tmp PYTHONUNBUFFERED=1
USER 1000:1000
EXPOSE 8080
CMD ["uvicorn", "registry.api:app", "--host", "0.0.0.0", "--port", "8080"]
