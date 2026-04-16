# MCP Spine — Benchmarks

Real-world token savings measured on actual MCP server tool schemas.

## Schema Minification

Tested on 12 representative tools across filesystem, SQLite, knowledge graph, and Brave Search servers.

### By Level

| Level | Description | Characters | Est. Tokens | Savings |
|-------|------------|------------|-------------|---------|
| 0 | Off (passthrough) | 4,104 | ~1,026 | 0% |
| 1 | Light (strip metadata) | 3,637 | ~909 | 11% |
| 2 | Standard (strip descriptions + defaults) | 2,788 | ~697 | 32% |
| 3 | Aggressive (flatten nested) | 2,788 | ~697 | 32% |

**Level 2 is the default.** It strips parameter descriptions, defaults, and metadata while preserving all type information and required fields. Safe for all tools.

### Per-Tool Breakdown (Level 2)

| Tool | Original | Minified | Savings |
|------|----------|----------|---------|
| read_file | 586 chars | 242 chars | 59% |
| write_file | 425 chars | 208 chars | 51% |
| search_files | 614 chars | 317 chars | 48% |
| list_directory | 325 chars | 209 chars | 36% |
| brave_web_search | 317 chars | 227 chars | 28% |
| search_nodes | 267 chars | 209 chars | 22% |
| read_query | 239 chars | 189 chars | 21% |
| create_table | 236 chars | 187 chars | 21% |
| describe_table | 257 chars | 205 chars | 20% |
| write_query | 253 chars | 210 chars | 17% |
| list_tables | 133 chars | 133 chars | 0% |
| create_entities | 428 chars | 428 chars | 0% |

**Key insight:** Tools with verbose descriptions and many parameter descriptions see the largest savings (50-60%). Minimal tools with no descriptions see no change — minification never removes structural information.

### Scaling with Tool Count

Token savings compound with more tools. Schema overhead is per-tool, so with 40+ tools the absolute savings become significant:

| Tool Count | Raw (est.) | Minified L2 (est.) | Savings |
|-----------|-----------|-------------------|---------|
| 12 tools | ~1,026 tokens | ~697 tokens | 329 tokens |
| 30 tools | ~2,565 tokens | ~1,743 tokens | 822 tokens |
| 57 tools | ~4,874 tokens | ~3,314 tokens | 1,560 tokens |

At Anthropic's API pricing, 1,560 tokens saved per request across a full workday of tool calls adds up.

### How Savings Vary

Savings depend on how verbose your tool schemas are:

- **High savings (40-60%):** Tools with long descriptions, many parameters with descriptions, default values, and metadata fields. Common in filesystem and GitHub MCP servers.
- **Medium savings (20-35%):** Tools with moderate descriptions. Common in database and search servers.
- **Low savings (0-15%):** Tools with minimal or no descriptions, or tools with complex nested schemas that Level 2 doesn't flatten.

The 61% figure cited in marketing materials was measured on the GitHub MCP server's verbose tool schemas (create_or_update_file, push_files, etc.), which have especially detailed parameter descriptions.

## Running Benchmarks

Generate benchmarks for your own tool set:

```bash
python benchmark.py
```

Or use the built-in comparison:

```python
from spine.minifier import SchemaMinifier

m = SchemaMinifier(level=2)
result = m.compare(your_tools)
print(f"Savings: {result['savings_pct']:.1f}%")
```

## Methodology

- **Character count** is used as the primary metric (correlates linearly with token count for JSON)
- **Token estimates** use a rough 4 characters per token ratio
- **Level 2** is tested as the default — it provides the best balance of savings and safety
- All measurements use the same tool schemas served by a real MCP Spine instance
