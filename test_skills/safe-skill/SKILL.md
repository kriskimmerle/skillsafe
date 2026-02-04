---
name: markdown-formatter
description: Format and clean up Markdown files. Fix heading levels, normalize lists, add table of contents, and ensure consistent style. Use when the user wants to format, lint, or clean up Markdown documents.
license: MIT
metadata:
  author: dev-tools
  version: "1.0.0"
---

# Markdown Formatter

Formats and cleans up Markdown files following consistent style rules.

## Features

- Fix heading hierarchy (no skipped levels)
- Normalize list markers (consistent `-` or `*`)
- Add or update table of contents
- Fix trailing whitespace
- Ensure files end with newline
- Format tables with aligned columns

## Usage

When the user asks to format a Markdown file:

1. Read the target file
2. Apply formatting rules
3. Write the formatted content back
4. Report what changed

### Formatting Rules

**Headings:**
- Ensure a single H1 at the top
- No skipped heading levels (H1 → H3 without H2)
- Add blank line before and after headings

**Lists:**
- Use `-` for unordered lists
- Use `1.` for ordered lists (auto-number)
- Indent nested lists with 2 spaces

**Code blocks:**
- Ensure language identifier on fenced blocks
- Use triple backticks (not tildes)

**Tables:**
- Align columns with padding
- Ensure header separator row exists

## Example

Input:
```markdown
# Title
### Skipped heading
* Mixed
- list
- markers
```

Output:
```markdown
# Title

## Skipped heading

- Mixed
- list
- markers
```

## Notes

- Always create a backup before modifying files
- Report the number of changes made
- Respect `.editorconfig` if present in the project
