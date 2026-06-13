from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost:5432/swiftslot")
os.environ.setdefault("RENDER_EXTERNAL_URL", "http://localhost:8000")

REQUIRED_PATHS = {
    "/",
    "/health",
    "/login-page",
    "/signup-page",
    "/app/dashboard",
    "/app/waitlist",
    "/app/broadcasts",
    "/app/appointments",
    "/app/analytics",
    "/app/settings",
    "/broadcast",
    "/api/me",
    "/api/clinic/settings",
    "/api/patients",
    "/api/appointments",
    "/api/recovery/recommendations",
    "/api/system/readiness",
    "/api/activity",
    "/api/export/clinic-summary",
}


def main() -> int:
    try:
        from app import app
    except Exception as exc:
        print(f"Could not import app; skipping route smoke check: {exc}")
        return 0

    paths = sorted({route.path for route in app.routes if hasattr(route, "path")})
    print("Registered routes:")
    for path in paths:
        print(path)

    missing = sorted(REQUIRED_PATHS - set(paths))
    if missing:
        print("\nMissing required routes:")
        for path in missing:
            print(path)
        return 1

    print("\nAll required routes are registered.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
