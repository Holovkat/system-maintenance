---
name: help
description: "Show the System Maintenance toolbox when the user says system-maintenance, system-maintenance:help or asks for its available tools."
---

# System Maintenance

Run the [toolbox entry point](../../scripts/system_maintenance.py) with `help`:

```bash
python3 "<this-skill-directory>/../../scripts/system_maintenance.py" help
```

Present its command table. [commands.json](../../commands.json) is the single
command index; new tools add their own skill and registry entry. `system-maintenance`
alone and `system-maintenance: help` select this menu. A selected command loads
its registered skill. Help performs no audit or cleanup.

The collection is installed globally, so invocation does not depend on the
current project. Its scope is the local machine and mounted disks.
