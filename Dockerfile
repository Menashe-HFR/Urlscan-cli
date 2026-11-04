FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 URLSCAN_DATABASE=/data/studio.db
WORKDIR /app
COPY pyproject.toml ./
COPY urlscan_studio ./urlscan_studio
RUN pip install --no-cache-dir . && useradd --create-home studio && mkdir /data && chown studio /data
USER studio
EXPOSE 4180
CMD ["uvicorn","urlscan_studio.app:create_app","--factory","--host","0.0.0.0","--port","4180","--workers","1"]
