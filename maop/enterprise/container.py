"""MAOP Enterprise Container Orchestration.

Provides Docker/Kubernetes deployment configurations:
  - Dockerfile generation
  - docker-compose.yml for local dev
  - Kubernetes manifests for production
  - Health check and readiness probes
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)


class ContainerConfig(BaseModel):
    image_name: str = "maop-enterprise"
    image_tag: str = "latest"
    registry: str = ""
    replicas: int = 2
    cpu_limit: str = "2"
    memory_limit: str = "4Gi"
    cpu_request: str = "500m"
    memory_request: str = "1Gi"
    health_check_path: str = "/api/health"
    health_check_interval_s: int = 30
    port: int = 9079
    env_vars: dict[str, str] = Field(default_factory=dict)
    volumes: list[str] = Field(default_factory=list)


class ContainerOrchestrator:
    """Enterprise container orchestration helper."""

    def __init__(self, config: ContainerConfig | None = None) -> None:
        require_feature(FeatureFlag.MULTI_USER)
        self._config = config or ContainerConfig()

    @property
    def config(self) -> ContainerConfig:
        return self._config

    def _image_ref(self) -> str:
        """Build a legal image reference: ``name:tag`` or ``registry/name:tag``.

        registry 为空时省略前缀（旧实现会输出 ``/name:tag`` 这类非法镜像名）。
        """
        registry = self._config.registry.strip()
        image = f"{self._config.image_name}:{self._config.image_tag}"
        return f"{registry}/{image}" if registry else image

    def generate_dockerfile(self) -> str:
        return f"""FROM python:3.12-slim

WORKDIR /app
COPY py/ /app/py/
COPY config/ /app/config/
COPY dashboard/ /app/dashboard/
COPY dashboard-enterprise/ /app/dashboard-enterprise/

RUN pip install --no-cache-dir /app/py/

ENV MAOP_EDITION=enterprise
ENV MAOP_AUTH=1
ENV MAOP_TLS=1

EXPOSE {self._config.port}
HEALTHCHECK --interval={self._config.health_check_interval_s}s --timeout=5s --retries=3 \\
    CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:{self._config.port}{self._config.health_check_path}')" || exit 1

CMD ["python", "-m", "maop.dashboard.server"]
"""

    def generate_docker_compose(self) -> str:
        return f"""version: "3.8"
services:
  maop:
    image: {self._config.image_name}:{self._config.image_tag}
    ports:
      - "{self._config.port}:{self._config.port}"
    environment:
      MAOP_EDITION: enterprise
      MAOP_AUTH: "1"
      MAOP_TLS: "1"
      MAOP_STORAGE_BACKEND: postgresql
      MAOP_CACHE_BACKEND: redis
      MAOP_QUEUE_BACKEND: rabbitmq
    depends_on:
      - postgres
      - redis
      - rabbitmq
    volumes:
      - maop-data:/app/data

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: maop
      POSTGRES_USER: maop
      POSTGRES_PASSWORD: ${{MAOP_PG_PASSWORD:?Set MAOP_PG_PASSWORD environment variable}}
    volumes:
      - pg-data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    # requirepass 从环境变量 REDIS_PASSWORD 读取；未设置时以无密码模式启动
    #（仅本地开发），生产环境必须设置 REDIS_PASSWORD。
    environment:
      REDIS_PASSWORD: ${{REDIS_PASSWORD:-}}
    command: ["sh", "-c", 'if [ -n "$$REDIS_PASSWORD" ]; then exec redis-server --requirepass "$$REDIS_PASSWORD"; else exec redis-server; fi']
    volumes:
      - redis-data:/data

  rabbitmq:
    image: rabbitmq:3-management-alpine
    ports:
      # management UI 默认只绑定本机，避免暴露到外网
      - "127.0.0.1:15672:15672"
    volumes:
      - rmq-data:/var/lib/rabbitmq

volumes:
  maop-data:
  pg-data:
  redis-data:
  rmq-data:
"""

    def generate_k8s_manifest(self) -> str:
        return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: maop-enterprise
  labels:
    app: maop
spec:
  replicas: {self._config.replicas}
  selector:
    matchLabels:
      app: maop
  template:
    metadata:
      labels:
        app: maop
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
      - name: maop
        image: {self._image_ref()}
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: {self._config.port}
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
        resources:
          requests:
            cpu: "{self._config.cpu_request}"
            memory: "{self._config.memory_request}"
          limits:
            cpu: "{self._config.cpu_limit}"
            memory: "{self._config.memory_limit}"
        livenessProbe:
          httpGet:
            path: {self._config.health_check_path}
            port: {self._config.port}
          periodSeconds: {self._config.health_check_interval_s}
        readinessProbe:
          httpGet:
            path: {self._config.health_check_path}
            port: {self._config.port}
          initialDelaySeconds: 5
          periodSeconds: 10
        env:
        - name: MAOP_EDITION
          value: "enterprise"
        # MAOP_PG_* 占位：实际值应通过 Secret（如 maop-pg-secret）注入，
        # 切勿在 manifest 中明文填写数据库口令。
        - name: MAOP_PG_HOST
          valueFrom:
            secretKeyRef:
              name: maop-pg-secret
              key: host
        - name: MAOP_PG_PORT
          valueFrom:
            secretKeyRef:
              name: maop-pg-secret
              key: port
        - name: MAOP_PG_USER
          valueFrom:
            secretKeyRef:
              name: maop-pg-secret
              key: user
        - name: MAOP_PG_PASSWORD
          valueFrom:
            secretKeyRef:
              name: maop-pg-secret
              key: password
        - name: MAOP_PG_DBNAME
          valueFrom:
            secretKeyRef:
              name: maop-pg-secret
              key: dbname
---
apiVersion: v1
kind: Service
metadata:
  name: maop-service
spec:
  selector:
    app: maop
  ports:
  - port: 80
    targetPort: {self._config.port}
  type: ClusterIP
"""
