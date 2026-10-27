FROM mitmproxy/mitmproxy:12.3.0

USER root
COPY proxy/egress_filter.py proxy/network_policy.py /opt/scamshield/
RUN chmod 0444 /opt/scamshield/egress_filter.py /opt/scamshield/network_policy.py
USER 1000:1000
ENTRYPOINT ["mitmdump"]
CMD ["--mode", "regular", "--listen-host", "0.0.0.0", "--listen-port", "8080", "--set", "connection_strategy=lazy", "-s", "/opt/scamshield/egress_filter.py"]
