# Databricks IP Functions Showcase

A Databricks notebook that demonstrates every built-in [IP address function](https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-ip-functions) in Databricks SQL, using OCSF-style cyber security telemetry.

Functions covered: `ip_host`, `ip_version`, `ip_as_binary`, `ip_as_string`, `ip_cidr`, `ip_cidr_contains`, `ip_network` / `ip_network_first` / `ip_network_last`, `ip_prefix_length`, and the `try_*` safe variants — plus two practical use cases (private vs. public classification, subnet-level traffic analysis).

## Parameterized — point it at your own data

The notebook is driven by two widgets at the top:

| Widget    | Default           | Purpose                                     |
|-----------|-------------------|---------------------------------------------|
| `catalog` | `main`            | Unity Catalog catalog holding your tables   |
| `schema`  | `cyber_demo_gold` | Schema holding the three tables below       |

The **Setup** cell reads the widgets and runs `USE CATALOG` / `USE SCHEMA`, so every SQL cell references its tables unqualified. Nothing is hardcoded — set the widgets, then **Run All** (or run the Setup cell first).

## Expected tables

The notebook expects three OCSF-style gold tables in the selected `catalog.schema`:

| Table                  | Columns used                                                        |
|------------------------|---------------------------------------------------------------------|
| `network_activity`     | `src_endpoint.ip`, `dst_endpoint.ip`                                |
| `http_activity`        | `src_endpoint.ip`, `dst_endpoint.ip`, `traffic.bytes`               |
| `vulnerability_finding`| `device.ip` (JSON array of strings)                                 |

Any dataset matching this schema will work; the IP functions themselves are the focus.

## Usage

1. Import `ip_functions_showcase.py` into a Databricks workspace (**Workspace → Import**, or via the CLI / Repos). It imports as a notebook.
2. Attach to a SQL warehouse or a cluster.
3. Set the `catalog` and `schema` widgets to where your tables live.
4. **Run All**.

## Requirements

- A Databricks workspace with Unity Catalog and SQL warehouse (or DBR cluster) access.
- The three tables above in the catalog/schema you point the widgets at.
