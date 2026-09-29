# Databricks notebook source
# DBTITLE 1,Title and Introduction
# MAGIC %md
# MAGIC # Databricks IP Functions Showcase
# MAGIC
# MAGIC This notebook demonstrates all built-in IP address functions available in Databricks SQL, as documented at the [IP Functions Reference](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-ip-functions). Each function is illustrated using OCSF-style cyber security data, covering HTTP activity, network activity, and vulnerability findings.
# MAGIC
# MAGIC **Parameterized:** set the **`catalog`** and **`schema`** widgets at the top of the notebook to point it at your own data, then **Run All** (or run the *Setup* cell first). The notebook expects three tables in that schema: `network_activity`, `http_activity`, and `vulnerability_finding`.

# COMMAND ----------

# DBTITLE 1,Setup — Catalog & Schema Widgets
# Create widgets so this notebook can be pointed at any catalog / schema that holds
# the OCSF-style gold tables used below (network_activity, http_activity,
# vulnerability_finding). Change the values in the widget bar at the top of the notebook.
dbutils.widgets.text("catalog", "main", "Catalog")
dbutils.widgets.text("schema", "cyber_demo_gold", "Schema")

catalog = dbutils.widgets.get("catalog")
schema = dbutils.widgets.get("schema")

# Set the session defaults so every %sql cell below can use unqualified table names.
spark.sql(f"USE CATALOG `{catalog}`")
spark.sql(f"USE SCHEMA `{schema}`")

print(f"Using catalog `{catalog}`, schema `{schema}`")

# COMMAND ----------

# DBTITLE 1,ip_host Section Header
# MAGIC %md
# MAGIC ## ip_host — Canonical IP Address
# MAGIC Returns the host IP address from a string, normalizing it to its canonical form.

# COMMAND ----------

# DBTITLE 1,ip_host Demo
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_endpoint.ip AS original_ip,
# MAGIC   ip_host(src_endpoint.ip) AS canonical_ip
# MAGIC FROM network_activity
# MAGIC WHERE src_endpoint.ip IS NOT NULL
# MAGIC LIMIT 10

# COMMAND ----------

# DBTITLE 1,ip_version Section Header
# MAGIC %md
# MAGIC ## ip_version — Detect IP Version
# MAGIC Returns the IP version number (4 for IPv4, 6 for IPv6) of a given IP address string.

# COMMAND ----------

# DBTITLE 1,ip_version Demo
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_endpoint.ip AS source_ip,
# MAGIC   ip_version(src_endpoint.ip) AS src_ip_version,
# MAGIC   dst_endpoint.ip AS dest_ip,
# MAGIC   ip_version(dst_endpoint.ip) AS dst_ip_version
# MAGIC FROM http_activity
# MAGIC WHERE src_endpoint.ip IS NOT NULL
# MAGIC   AND dst_endpoint.ip IS NOT NULL
# MAGIC LIMIT 10

# COMMAND ----------

# DBTITLE 1,ip_as_binary and ip_as_string Section Header
# MAGIC %md
# MAGIC ## ip_as_binary and ip_as_string — Binary/String Conversion
# MAGIC Demonstrates round-tripping an IP address: string → binary → hex representation → back to string.

# COMMAND ----------

# DBTITLE 1,ip_as_binary and ip_as_string Demo
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_endpoint.ip AS original_ip,
# MAGIC   ip_as_binary(src_endpoint.ip) AS ip_binary,
# MAGIC   hex(ip_as_binary(src_endpoint.ip)) AS ip_hex,
# MAGIC   ip_as_string(ip_as_binary(src_endpoint.ip)) AS round_tripped_ip
# MAGIC FROM http_activity
# MAGIC WHERE src_endpoint.ip IS NOT NULL
# MAGIC LIMIT 10

# COMMAND ----------

# DBTITLE 1,ip_cidr Section Header
# MAGIC %md
# MAGIC ## ip_cidr — Canonical CIDR Blocks
# MAGIC Returns the canonical form of a CIDR notation string.

# COMMAND ----------

# DBTITLE 1,ip_cidr Demo
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_endpoint.ip AS original_ip,
# MAGIC   concat(src_endpoint.ip, '/24') AS constructed_cidr,
# MAGIC   ip_cidr(concat(src_endpoint.ip, '/24')) AS canonical_cidr
# MAGIC FROM network_activity
# MAGIC WHERE src_endpoint.ip IS NOT NULL
# MAGIC LIMIT 10

# COMMAND ----------

# DBTITLE 1,ip_cidr_contains Section Header
# MAGIC %md
# MAGIC ## ip_cidr_contains — Subnet Membership Check
# MAGIC Checks whether a given IP address falls within a specified CIDR subnet range.

# COMMAND ----------

# DBTITLE 1,ip_cidr_contains Demo
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_endpoint.ip AS source_ip,
# MAGIC   ip_cidr_contains('10.0.0.0/8', src_endpoint.ip) AS in_10_network,
# MAGIC   ip_cidr_contains('172.16.0.0/12', src_endpoint.ip) AS in_172_network,
# MAGIC   ip_cidr_contains('192.168.0.0/16', src_endpoint.ip) AS in_192_network,
# MAGIC   (
# MAGIC     ip_cidr_contains('10.0.0.0/8', src_endpoint.ip)
# MAGIC     OR ip_cidr_contains('172.16.0.0/12', src_endpoint.ip)
# MAGIC     OR ip_cidr_contains('192.168.0.0/16', src_endpoint.ip)
# MAGIC   ) AS is_private
# MAGIC FROM network_activity
# MAGIC WHERE src_endpoint.ip IS NOT NULL
# MAGIC LIMIT 20

# COMMAND ----------

# DBTITLE 1,ip_network ip_network_last Section Header
# MAGIC %md
# MAGIC ## ip_network, ip_network_first, ip_network_last — Network Range Boundaries
# MAGIC For a given CIDR block, extract the first (network) address, the last (broadcast) address, and the prefix length.

# COMMAND ----------

# DBTITLE 1,ip_network and ip_network_last Demo
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_endpoint.ip AS original_ip,
# MAGIC   concat(src_endpoint.ip, '/24') AS cidr_block,
# MAGIC   ip_network(concat(src_endpoint.ip, '/24')) AS network_first,
# MAGIC   ip_network_last(concat(src_endpoint.ip, '/24')) AS network_last,
# MAGIC   ip_prefix_length(concat(src_endpoint.ip, '/24')) AS prefix_length
# MAGIC FROM http_activity
# MAGIC WHERE src_endpoint.ip IS NOT NULL
# MAGIC LIMIT 10

# COMMAND ----------

# DBTITLE 1,ip_prefix_length Section Header
# MAGIC %md
# MAGIC ## ip_prefix_length — Extract Prefix Length
# MAGIC Extracts the prefix length (subnet mask size) from a CIDR notation string.

# COMMAND ----------

# DBTITLE 1,ip_prefix_length Demo
# MAGIC %sql
# MAGIC SELECT
# MAGIC   d_ip AS device_ip,
# MAGIC   ip_prefix_length(concat(d_ip, '/8')) AS prefix_8,
# MAGIC   ip_prefix_length(concat(d_ip, '/16')) AS prefix_16,
# MAGIC   ip_prefix_length(concat(d_ip, '/24')) AS prefix_24,
# MAGIC   ip_prefix_length(concat(d_ip, '/32')) AS prefix_32
# MAGIC FROM vulnerability_finding
# MAGIC LATERAL VIEW EXPLODE(from_json(device.ip, 'ARRAY<STRING>')) t AS d_ip
# MAGIC WHERE d_ip IS NOT NULL
# MAGIC LIMIT 10

# COMMAND ----------

# DBTITLE 1,try_* Safe Variants Section Header
# MAGIC %md
# MAGIC ## try_* Safe Variants — Graceful Error Handling
# MAGIC The `try_` prefixed variants return NULL instead of raising errors for invalid inputs. Compare valid IPs from data with invalid literals.

# COMMAND ----------

# DBTITLE 1,try_* Safe Variants Demo
# MAGIC %sql
# MAGIC WITH valid_ips AS (
# MAGIC   SELECT src_endpoint.ip AS test_input, 'valid' AS input_type
# MAGIC   FROM http_activity
# MAGIC   WHERE src_endpoint.ip IS NOT NULL
# MAGIC   LIMIT 3
# MAGIC ),
# MAGIC invalid_ips AS (
# MAGIC   SELECT col1 AS test_input, 'invalid' AS input_type
# MAGIC   FROM VALUES ('not_an_ip'), ('999.999.999.999'), ('') AS t(col1)
# MAGIC ),
# MAGIC combined AS (
# MAGIC   SELECT * FROM valid_ips
# MAGIC   UNION ALL
# MAGIC   SELECT * FROM invalid_ips
# MAGIC )
# MAGIC SELECT
# MAGIC   test_input,
# MAGIC   input_type,
# MAGIC   try_ip_host(test_input) AS try_host,
# MAGIC   hex(try_ip_as_binary(test_input)) AS try_binary_hex,
# MAGIC   try_ip_as_string(try_ip_as_binary(test_input)) AS try_string_roundtrip,
# MAGIC   try_ip_cidr(concat(test_input, '/24')) AS try_cidr
# MAGIC FROM combined

# COMMAND ----------

# DBTITLE 1,Private vs Public IP Classification Header
# MAGIC %md
# MAGIC ## Practical Use Case: Private vs Public IP Classification
# MAGIC Classify all source and destination IPs as **Private** (RFC 1918) or **Public** using `ip_cidr_contains()`, then count traffic volume by classification.

# COMMAND ----------

# DBTITLE 1,Private vs Public IP Classification
# MAGIC %sql
# MAGIC SELECT
# MAGIC   CASE
# MAGIC     WHEN ip_cidr_contains('10.0.0.0/8', ip)
# MAGIC       OR ip_cidr_contains('172.16.0.0/12', ip)
# MAGIC       OR ip_cidr_contains('192.168.0.0/16', ip)
# MAGIC     THEN 'Private'
# MAGIC     ELSE 'Public'
# MAGIC   END AS ip_classification,
# MAGIC   COUNT(*) AS traffic_count
# MAGIC FROM (
# MAGIC   SELECT src_endpoint.ip AS ip
# MAGIC   FROM network_activity
# MAGIC   WHERE src_endpoint.ip IS NOT NULL
# MAGIC   UNION ALL
# MAGIC   SELECT dst_endpoint.ip AS ip
# MAGIC   FROM network_activity
# MAGIC   WHERE dst_endpoint.ip IS NOT NULL
# MAGIC ) all_ips
# MAGIC GROUP BY ip_classification
# MAGIC ORDER BY traffic_count DESC

# COMMAND ----------

# DBTITLE 1,Subnet-Level Traffic Analysis Header
# MAGIC %md
# MAGIC ## Practical Use Case: Subnet-Level Traffic Analysis
# MAGIC Extract the /24 network from source IPs, then aggregate traffic counts and total bytes per subnet.

# COMMAND ----------

# DBTITLE 1,Subnet-Level Traffic Analysis
# MAGIC %sql
# MAGIC SELECT
# MAGIC   ip_network(concat(src_endpoint.ip, '/24')) AS subnet,
# MAGIC   COUNT(*) AS request_count,
# MAGIC   SUM(COALESCE(traffic.bytes, 0)) AS total_bytes
# MAGIC FROM http_activity
# MAGIC WHERE src_endpoint.ip IS NOT NULL
# MAGIC GROUP BY subnet
# MAGIC ORDER BY request_count DESC
# MAGIC LIMIT 20
