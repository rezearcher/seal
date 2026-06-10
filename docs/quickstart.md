# Quickstart

> This file is superseded. See **[GETTING_STARTED.md](GETTING_STARTED.md)** for the current, verified quickstart guide.
>
> The content that was here was aspirational and contained several stale claims:
> - `pip install seal-vpe` (not on PyPI)
> - `seal genkey` writing `seal_private.key` / `seal_public.key` files (it uses `keys.db`)
> - `seal sign` / `seal verify` syntax without the key-store auto-resolution that now exists
> - No coverage of `seal epd`, `seal memory`, or `seal quickstart` subcommands
>
> The working one-command path is:
>
> ```bash
> pip install "git+https://github.com/rezearcher/seal.git"
> seal quickstart
> ```
