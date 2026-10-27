FROM mcr.microsoft.com/playwright/python:v1.64.1-noble

USER root
RUN python -m pip install --no-cache-dir playwright==1.64.1
COPY --chown=pwuser:pwuser worker/worker.py /opt/scamshield/sandbox_worker.py
COPY --chown=pwuser:pwuser proxy/network_policy.py /opt/scamshield/network_policy.py
RUN chmod 0555 /opt/scamshield/sandbox_worker.py /opt/scamshield/network_policy.py
USER pwuser
WORKDIR /tmp
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
