# Pulse
💓 We watch your websites so you can sleep.

## Run it 🏃
`pip install -r requirements.txt`, then `uvicorn app:app --port 8000` (Python 3.10+). Open http://localhost:8000, register, add a URL. Want instant data? `python seed.py` makes demo@example.com / demo-password-123 and a public page at /status/demo.

## Honest disclaimer
**This is a test app only, and it has never been run.** It's a local-only prototype, never deployed: one process, one SQLite file, one background loop. I wrote it without running it, so expect a typo or two. Don't deploy it, and don't point it at anything you can't afford to ping.

## Things that went wrong while building this 🙃
- A public URL can 302 you straight into 169.254.169.254, so every redirect hop gets re-validated now.
- One failed check = one incident = a very anxious dashboard. It takes three in a row now.

Stay up. 🫡
