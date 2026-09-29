# Databricks IP Functions Showcase
#
# Demonstrates the built-in Databricks SQL IP address functions:
# https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-ip-functions
#
# HOW TO USE: paste this whole file into ONE Python cell of a Databricks notebook and run it.
# The first run creates "catalog" and "schema" widgets at the top of the notebook.
# Type your catalog and schema into the widgets, then run the cell again.
#
# The schema must contain three OCSF-style tables:
#   network_activity       (src_endpoint.ip, dst_endpoint.ip)
#   http_activity          (src_endpoint.ip, dst_endpoint.ip, traffic.bytes)
#   vulnerability_finding  (device.ip as a JSON array of strings)

dbutils.widgets.text("catalog", "", "Catalog")
dbutils.widgets.text("schema", "", "Schema")

catalog = dbutils.widgets.get("catalog").strip()
schema = dbutils.widgets.get("schema").strip()

if not catalog or not schema:
    raise ValueError("Type a catalog and schema into the widgets at the top of the notebook, then run this cell again.")

# Set the session defaults so every query below can use unqualified table names.
spark.sql(f"USE CATALOG `{catalog.replace('`', '``')}`")
spark.sql(f"USE SCHEMA `{schema.replace('`', '``')}`")
print(f"Using catalog `{catalog}`, schema `{schema}`")

demos = [
    (
        "ip_host: Canonical IP Address",
        "Returns the host IP address from a string, normalizing it to its canonical form.",
        """
        SELECT
          src_endpoint.ip AS original_ip,
          ip_host(src_endpoint.ip) AS canonical_ip
        FROM network_activity
        WHERE src_endpoint.ip IS NOT NULL
        LIMIT 10
        """,
    ),
    (
        "ip_version: Detect IP Version",
        "Returns the IP version number (4 for IPv4, 6 for IPv6) of a given IP address string.",
        """
        SELECT
          src_endpoint.ip AS source_ip,
          ip_version(src_endpoint.ip) AS src_ip_version,
          dst_endpoint.ip AS dest_ip,
          ip_version(dst_endpoint.ip) AS dst_ip_version
        FROM http_activity
        WHERE src_endpoint.ip IS NOT NULL
          AND dst_endpoint.ip IS NOT NULL
        LIMIT 10
        """,
    ),
    (
        "ip_as_binary and ip_as_string: Binary/String Conversion",
        "Round trips an IP address: string to binary to hex, then back to string.",
        """
        SELECT
          src_endpoint.ip AS original_ip,
          ip_as_binary(src_endpoint.ip) AS ip_binary,
          hex(ip_as_binary(src_endpoint.ip)) AS ip_hex,
          ip_as_string(ip_as_binary(src_endpoint.ip)) AS round_tripped_ip
        FROM http_activity
        WHERE src_endpoint.ip IS NOT NULL
        LIMIT 10
        """,
    ),
    (
        "ip_cidr: Canonical CIDR Blocks",
        "Returns the canonical form of a CIDR notation string.",
        """
        SELECT
          src_endpoint.ip AS original_ip,
          concat(src_endpoint.ip, '/24') AS constructed_cidr,
          ip_cidr(concat(src_endpoint.ip, '/24')) AS canonical_cidr
        FROM network_activity
        WHERE src_endpoint.ip IS NOT NULL
        LIMIT 10
        """,
    ),
    (
        "ip_cidr_contains: Subnet Membership Check",
        "Checks whether a given IP address falls within a specified CIDR subnet range.",
        """
        SELECT
          src_endpoint.ip AS source_ip,
          ip_cidr_contains('10.0.0.0/8', src_endpoint.ip) AS in_10_network,
          ip_cidr_contains('172.16.0.0/12', src_endpoint.ip) AS in_172_network,
          ip_cidr_contains('192.168.0.0/16', src_endpoint.ip) AS in_192_network,
          (
            ip_cidr_contains('10.0.0.0/8', src_endpoint.ip)
            OR ip_cidr_contains('172.16.0.0/12', src_endpoint.ip)
            OR ip_cidr_contains('192.168.0.0/16', src_endpoint.ip)
          ) AS is_private
        FROM network_activity
        WHERE src_endpoint.ip IS NOT NULL
        LIMIT 20
        """,
    ),
    (
        "ip_network, ip_network_last: Network Range Boundaries",
        "For a CIDR block, extracts the first (network) address, the last (broadcast) address, and the prefix length.",
        """
        SELECT
          src_endpoint.ip AS original_ip,
          concat(src_endpoint.ip, '/24') AS cidr_block,
          ip_network(concat(src_endpoint.ip, '/24')) AS network_first,
          ip_network_last(concat(src_endpoint.ip, '/24')) AS network_last,
          ip_prefix_length(concat(src_endpoint.ip, '/24')) AS prefix_length
        FROM http_activity
        WHERE src_endpoint.ip IS NOT NULL
        LIMIT 10
        """,
    ),
    (
        "ip_prefix_length: Extract Prefix Length",
        "Extracts the prefix length (subnet mask size) from a CIDR notation string.",
        """
        SELECT
          d_ip AS device_ip,
          ip_prefix_length(concat(d_ip, '/8')) AS prefix_8,
          ip_prefix_length(concat(d_ip, '/16')) AS prefix_16,
          ip_prefix_length(concat(d_ip, '/24')) AS prefix_24,
          ip_prefix_length(concat(d_ip, '/32')) AS prefix_32
        FROM vulnerability_finding
        LATERAL VIEW EXPLODE(from_json(device.ip, 'ARRAY<STRING>')) t AS d_ip
        WHERE d_ip IS NOT NULL
        LIMIT 10
        """,
    ),
    (
        "try_* Safe Variants: Graceful Error Handling",
        "The try_ variants return NULL instead of raising errors for invalid inputs. Compares valid IPs from the data with invalid literals.",
        """
        WITH valid_ips AS (
          SELECT src_endpoint.ip AS test_input, 'valid' AS input_type
          FROM http_activity
          WHERE src_endpoint.ip IS NOT NULL
          LIMIT 3
        ),
        invalid_ips AS (
          SELECT col1 AS test_input, 'invalid' AS input_type
          FROM VALUES ('not_an_ip'), ('999.999.999.999'), ('') AS t(col1)
        ),
        combined AS (
          SELECT * FROM valid_ips
          UNION ALL
          SELECT * FROM invalid_ips
        )
        SELECT
          test_input,
          input_type,
          try_ip_host(test_input) AS try_host,
          hex(try_ip_as_binary(test_input)) AS try_binary_hex,
          try_ip_as_string(try_ip_as_binary(test_input)) AS try_string_roundtrip,
          try_ip_cidr(concat(test_input, '/24')) AS try_cidr
        FROM combined
        """,
    ),
    (
        "Use Case: Private vs Public IP Classification",
        "Classifies all source and destination IPs as Private (RFC 1918) or Public with ip_cidr_contains(), then counts traffic by classification.",
        """
        SELECT
          CASE
            WHEN ip_cidr_contains('10.0.0.0/8', ip)
              OR ip_cidr_contains('172.16.0.0/12', ip)
              OR ip_cidr_contains('192.168.0.0/16', ip)
            THEN 'Private'
            ELSE 'Public'
          END AS ip_classification,
          COUNT(*) AS traffic_count
        FROM (
          SELECT src_endpoint.ip AS ip
          FROM network_activity
          WHERE src_endpoint.ip IS NOT NULL
          UNION ALL
          SELECT dst_endpoint.ip AS ip
          FROM network_activity
          WHERE dst_endpoint.ip IS NOT NULL
        ) all_ips
        GROUP BY ip_classification
        ORDER BY traffic_count DESC
        """,
    ),
    (
        "Use Case: Subnet-Level Traffic Analysis",
        "Extracts the /24 network from source IPs, then aggregates request counts and total bytes per subnet.",
        """
        SELECT
          ip_network(concat(src_endpoint.ip, '/24')) AS subnet,
          COUNT(*) AS request_count,
          SUM(COALESCE(traffic.bytes, 0)) AS total_bytes
        FROM http_activity
        WHERE src_endpoint.ip IS NOT NULL
        GROUP BY subnet
        ORDER BY request_count DESC
        LIMIT 20
        """,
    ),
]

for title, description, query in demos:
    displayHTML(f"<h2>{title}</h2><p>{description}</p>")
    display(spark.sql(query))
