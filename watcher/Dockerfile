FROM ghcr.io/google/osv-scanner:v2.7.0 AS osv
FROM composer:2 AS composer

FROM node:22-bookworm-slim

# Toolchains available to the AI fixer. Extend this list for your stack
# (e.g. golang, ruby-full, openjdk-17-jdk-headless, maven) and add the
# matching commands to `ai_allowed_commands` in repos.json.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ca-certificates curl unzip \
      python3 python3-pip python3-venv \
      php-cli php-xml php-mbstring php-curl php-zip php-intl php-bcmath php-gd php-mysql php-sqlite3 \
 && rm -rf /var/lib/apt/lists/* \
 && corepack enable

RUN pip3 install --no-cache-dir --break-system-packages semgrep==1.182.1
RUN npm install -g @anthropic-ai/claude-code@2.1.308 && npm cache clean --force

COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
COPY watch.py /app/watch.py

USER node
WORKDIR /home/node
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/app/watch.py"]
