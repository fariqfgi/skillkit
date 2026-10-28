#!/usr/bin/env python3 -I
"""
Parse nmap XML + httpx JSONL output into a structured service map.

Usage:
    python3 parse_results.py <nmap.xml> <httpx.jsonl> <target_host> <target_ip> <service_map.json>
"""
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Services that warrant immediate escalation if unauthenticated
CRITICAL_SERVICES = {
    9200: "Elasticsearch",
    9300: "Elasticsearch (transport)",
    6379: "Redis",
    27017: "MongoDB",
    27018: "MongoDB",
    2375: "Docker daemon (unauthenticated HTTP)",
    2376: "Docker daemon (TLS)",
    4001: "etcd",
    8500: "Consul",
    5601: "Kibana",
    9090: "Prometheus",
    3000: "Grafana (default)",
    8161: "ActiveMQ admin",
    61616: "ActiveMQ broker",
    5672: "RabbitMQ",
    15672: "RabbitMQ admin",
    11211: "Memcached",
    50070: "Hadoop NameNode",
    2181: "ZooKeeper",
}

HIGH_VALUE_SERVICES = {
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    636: "LDAPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    1521: "Oracle",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-alt (admin panel likely)",
    8443: "HTTPS-alt (admin panel likely)",
    8888: "HTTP-alt (Jupyter/dev)",
    9000: "HTTP-alt (PHP-FPM / SonarQube)",
    9443: "HTTPS-alt",
}


def parse_nmap_xml(xml_path: Path) -> list[dict]:
    services = []
    if not xml_path.exists():
        return services
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                port_id = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                service_el = port_el.find("service")
                svc_name = ""
                svc_product = ""
                svc_version = ""
                svc_extra = ""
                if service_el is not None:
                    svc_name = service_el.get("name", "")
                    svc_product = service_el.get("product", "")
                    svc_version = service_el.get("version", "")
                    svc_extra = service_el.get("extrainfo", "")

                risk = "low"
                if port_id in CRITICAL_SERVICES:
                    risk = "critical"
                elif port_id in HIGH_VALUE_SERVICES:
                    risk = "medium"

                services.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": svc_name,
                    "product": svc_product,
                    "version": svc_version,
                    "extra": svc_extra,
                    "risk": risk,
                    "known_service": CRITICAL_SERVICES.get(port_id) or HIGH_VALUE_SERVICES.get(port_id, ""),
                })
    except Exception as e:
        print(f"[!] nmap XML parse error: {e}", file=sys.stderr)
    return services


def parse_httpx_jsonl(jsonl_path: Path) -> list[dict]:
    web_services = []
    if not jsonl_path.exists():
        return web_services
    try:
        for line in jsonl_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                web_services.append({
                    "url": d.get("url", ""),
                    "status_code": d.get("status_code", 0),
                    "title": d.get("title", ""),
                    "tech": d.get("tech", []),
                    "web_server": d.get("web_server", ""),
                    "content_length": d.get("content_length", 0),
                })
            except Exception:
                pass
    except Exception as e:
        print(f"[!] httpx JSONL parse error: {e}", file=sys.stderr)
    return web_services


def main():
    if len(sys.argv) < 6:
        print(f"Usage: {sys.argv[0]} <nmap.xml> <httpx.jsonl> <target> <target_ip> <service_map.json>", file=sys.stderr)
        sys.exit(1)

    nmap_xml = Path(sys.argv[1])
    httpx_jsonl = Path(sys.argv[2])
    target = sys.argv[3]
    target_ip = sys.argv[4]
    out_file = Path(sys.argv[5])

    services = parse_nmap_xml(nmap_xml)
    web_services = parse_httpx_jsonl(httpx_jsonl)

    critical_alerts = [s for s in services if s["risk"] == "critical"]
    medium_alerts = [s for s in services if s["risk"] == "medium"]

    for alert in critical_alerts:
        print(f"[!!!] CRITICAL: Port {alert['port']} ({alert['known_service']}) is OPEN — check authentication!", file=sys.stderr)

    output = {
        "target": target,
        "target_ip": target_ip,
        "summary": {
            "total_open_ports": len(services),
            "critical_risk_ports": len(critical_alerts),
            "medium_risk_ports": len(medium_alerts),
            "web_services_found": len(web_services),
        },
        "critical_alerts": critical_alerts,
        "services": services,
        "web_services": web_services,
    }

    out_file.write_text(json.dumps(output, indent=2))
    print(f"[+] Service map written to {out_file}")
    print(f"    Open ports:    {len(services)}")
    print(f"    Critical:      {len(critical_alerts)}")
    print(f"    Web services:  {len(web_services)}")


if __name__ == "__main__":
    main()
