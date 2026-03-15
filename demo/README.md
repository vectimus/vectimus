# Demo GIF

Animated terminal recording showing Vectimus blocking dangerous commands in a simulated Claude Code session.

## Re-recording

Requires [asciinema](https://asciinema.org/) and [agg](https://github.com/asciinema/agg):

```bash
pipx install asciinema
cargo install --git https://github.com/asciinema/agg
```

Then run:

```bash
./demo/record.sh
```

This records `demo-session.sh` with asciinema and converts to `demo.gif` with agg.

## Files

- `demo-session.sh` -- scripted terminal session (edit this to change content)
- `record.sh` -- recording and conversion wrapper
- `demo.cast` -- intermediate asciinema recording (not committed)
