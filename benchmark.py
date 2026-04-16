"""Generate token savings benchmarks for MCP Spine."""
import json
from spine.minifier import SchemaMinifier

tools = [
    {"name": "read_file", "description": "Read the complete contents of a file as text. You can use this to read text files like source code, configuration files, documentation, etc. You can optionally specify line ranges to read specific portions of the file.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "The absolute path to the file to read"}, "tail": {"type": "number", "description": "Read only the last N lines of the file"}, "head": {"type": "number", "description": "Read only the first N lines of the file"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write content to a file. Creates the file if it does not exist, or overwrites it if it does. Only use this for new files or complete rewrites.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "The absolute path to the file"}, "content": {"type": "string", "description": "The content to write to the file"}}, "required": ["path", "content"]}},
    {"name": "list_directory", "description": "List all files and directories in the specified directory path. Returns entries with type indicators (file/directory).", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "The absolute path to the directory to list"}}, "required": ["path"]}},
    {"name": "search_files", "description": "Recursively search for files and directories matching a pattern. Searches through all subdirectories from the specified path. Use this to find files when you do not know the exact path.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "The starting directory path"}, "pattern": {"type": "string", "description": "The search pattern to match against file and directory names"}, "excludePatterns": {"type": "array", "items": {"type": "string"}, "description": "Patterns to exclude from results"}}, "required": ["path", "pattern"]}},
    {"name": "read_query", "description": "Execute a SELECT query on the SQLite database", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "The SELECT SQL query to execute"}}, "required": ["query"]}},
    {"name": "write_query", "description": "Execute an INSERT, UPDATE, or DELETE query on the SQLite database", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "The SQL query to execute"}}, "required": ["query"]}},
    {"name": "create_table", "description": "Create a new table in the SQLite database", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "The CREATE TABLE SQL statement"}}, "required": ["query"]}},
    {"name": "list_tables", "description": "List all tables in the SQLite database", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "describe_table", "description": "Get the schema information for a specific table", "inputSchema": {"type": "object", "properties": {"table_name": {"type": "string", "description": "The name of the table to describe"}}, "required": ["table_name"]}},
    {"name": "create_entities", "description": "Create multiple new entities in the knowledge graph", "inputSchema": {"type": "object", "properties": {"entities": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "entityType": {"type": "string"}, "observations": {"type": "array", "items": {"type": "string"}}}, "required": ["name", "entityType", "observations"]}}}, "required": ["entities"]}},
    {"name": "search_nodes", "description": "Search for nodes in the knowledge graph based on a query string", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "The search query to find matching nodes"}}, "required": ["query"]}},
    {"name": "brave_web_search", "description": "Performs a web search using the Brave Search API", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "The search query"}, "count": {"type": "number", "description": "Number of results (1-20, default 10)"}}, "required": ["query"]}},
]

print("=" * 60)
print("MCP Spine — Schema Minification Benchmarks")
print("=" * 60)
print(f"Tools: {len(tools)}")
print()

original = json.dumps(tools)
orig_chars = len(original)
orig_tokens = orig_chars // 4  # rough estimate

for level in range(4):
    m = SchemaMinifier(level=level)
    minified = json.dumps(m.minify_batch(tools))
    mini_chars = len(minified)
    mini_tokens = mini_chars // 4
    savings = (1 - mini_chars / orig_chars) * 100
    print(f"Level {level}: {orig_chars:,} -> {mini_chars:,} chars | ~{orig_tokens:,} -> ~{mini_tokens:,} tokens | {savings:.1f}% savings")

print()
print("Per-tool breakdown (Level 2):")
print("-" * 60)
m2 = SchemaMinifier(level=2)
for tool in tools:
    orig = len(json.dumps(tool))
    mini = len(json.dumps(m2.minify(tool)))
    pct = (1 - mini / orig) * 100
    print(f"  {tool['name']:25s} {orig:4d} -> {mini:4d} chars ({pct:.0f}%)")
