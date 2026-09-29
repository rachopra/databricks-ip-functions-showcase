# Databricks IP Functions Showcase

A single Python script that demonstrates every built-in [IP address function](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-ip-functions) in Databricks SQL, using OCSF-style cyber security telemetry.

Functions covered: `ip_host`, `ip_version`, `ip_as_binary`, `ip_as_string`, `ip_cidr`, `ip_cidr_contains`, `ip_network` / `ip_network_last`, `ip_prefix_length`, and the `try_*` safe variants, plus two practical use cases (private vs. public classification, subnet-level traffic analysis).

## Usage (copy and paste, no import needed)

1. Open a Python notebook in Databricks and attach it to serverless or a cluster.
2. Copy the full contents of [`ip_functions_showcase.py`](ip_functions_showcase.py) and paste it into **one** cell.
3. Run the cell. The first run creates `catalog` and `schema` widgets at the top of the notebook and asks you to fill them in.
4. Type your catalog and schema into the widgets and run the cell again. Each demo prints a heading followed by its result table.

No catalog or schema is hardcoded. The script runs `USE CATALOG` / `USE SCHEMA` from the widget values and every query uses unqualified table names.

## Expected tables

The selected `catalog.schema` needs three OCSF-style tables:

| Table                   | Columns used                                          |
|-------------------------|-------------------------------------------------------|
| `network_activity`      | `src_endpoint.ip`, `dst_endpoint.ip`                  |
| `http_activity`         | `src_endpoint.ip`, `dst_endpoint.ip`, `traffic.bytes` |
| `vulnerability_finding` | `device.ip` (JSON array of strings)                   |
