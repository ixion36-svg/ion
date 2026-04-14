"""Load test for ION.

Models a realistic mix of SOC analyst traffic:
- High-frequency notification polling (every few seconds in real UI)
- Periodic list views (alerts, cases, playbooks, observables)
- Occasional dashboard + AI history
- Login once per simulated user, cookie reused for all subsequent requests

Run headless from the host:

    docker run --rm \\
      --network ixion_ion-net \\
      -v "$PWD/loadtest:/mnt/locust" \\
      -w /mnt/locust \\
      locustio/locust:latest \\
      -f locustfile.py --host http://ion:8000 \\
      --headless -u 50 -r 5 -t 60s \\
      --csv /mnt/locust/baseline

Flags:
  -u N    target user count
  -r N    spawn rate (users/sec)
  -t Ns   total run time
  --csv   prefix for stats CSV output (creates _stats.csv, _failures.csv, etc.)
"""

import random
from locust import HttpUser, task, between, events
from locust.exception import StopUser


# Pool of seeded test users that actually exist in the DB. Each simulated
# locust user picks one at random so the audit log + per-user state is
# spread realistically across analysts.
TEST_USERS = [
    ("admin", "admin2025"),
    ("soc_sarah", "user2025"),
    ("soc_marcus", "user2025"),
    ("soc_priya", "user2025"),
    ("soc_james", "user2025"),
    ("soc_elena", "user2025"),
    ("soc_tom", "user2025"),
    ("soc_aisha", "user2025"),
    ("soc_chen", "user2025"),
]


class IonAnalyst(HttpUser):
    """Simulates a SOC analyst clicking around ION."""

    # Think time between actions — bracketing a real user's pace.
    wait_time = between(1, 4)

    def on_start(self):
        """Login once, persist the session cookie for the user lifetime.

        On failure we mark this individual user as dead (no tasks run) but
        DO NOT kill the whole test — a flaky single login shouldn't tank a
        baseline measurement.
        """
        self._authed = False
        username, password = random.choice(TEST_USERS)
        with self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            name="POST /api/auth/login",
            catch_response=True,
        ) as r:
            if r.status_code != 200:
                r.failure(f"login failed for {username}: {r.status_code} {r.text[:120]}")
                raise StopUser()
            self._authed = True

    # =====================================================================
    # Hot polling endpoint — by far the most frequent real-world call
    # =====================================================================

    @task(20)
    def notifications_unread(self):
        self.client.get(
            "/api/notifications/unread-count",
            name="GET /api/notifications/unread-count",
        )

    # =====================================================================
    # List endpoints — visited when an analyst opens a tab
    # =====================================================================

    @task(8)
    def list_cases(self):
        self.client.get(
            "/api/elasticsearch/alerts/cases",
            name="GET /api/elasticsearch/alerts/cases",
        )

    @task(6)
    def list_playbooks(self):
        self.client.get("/api/playbooks", name="GET /api/playbooks")

    @task(6)
    def list_notifications(self):
        self.client.get("/api/notifications", name="GET /api/notifications")

    @task(5)
    def list_observables(self):
        self.client.get(
            "/api/observables?limit=50",
            name="GET /api/observables",
        )

    @task(4)
    def ai_history(self):
        self.client.get(
            "/api/ai/history/sessions",
            name="GET /api/ai/history/sessions",
        )

    # =====================================================================
    # Page renders — analyst opens the actual HTML
    # =====================================================================

    @task(3)
    def dashboard_page(self):
        self.client.get("/", name="GET /")

    @task(2)
    def alerts_page(self):
        self.client.get("/alerts", name="GET /alerts")

    @task(2)
    def cases_page(self):
        self.client.get("/cases", name="GET /cases")


# =========================================================================
# Stats reporter — print a one-line summary at the end
# =========================================================================

@events.quitting.add_listener
def _print_summary(environment, **kwargs):
    s = environment.stats.total
    print()
    print("=" * 72)
    print("BASELINE SUMMARY")
    print("=" * 72)
    print(f"  total requests:  {s.num_requests}")
    print(f"  failures:        {s.num_failures} ({s.fail_ratio*100:.2f}%)")
    print(f"  RPS:             {s.total_rps:.1f}")
    print(f"  median:          {s.median_response_time} ms")
    print(f"  p95:             {s.get_response_time_percentile(0.95):.0f} ms")
    print(f"  p99:             {s.get_response_time_percentile(0.99):.0f} ms")
    print(f"  max:             {s.max_response_time:.0f} ms")
    print("=" * 72)
