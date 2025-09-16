import hashlib

import copy
import requests
import datetime
import json
import time
import os

PASS_ICON = "✅"
FAIL_ICON = "❌"
UNKNOWN_ICON = "🟡"

state_file = os.environ.get("STATE_PATH", "state/state.json")
expectations_file = "expectations.json"


class VerificationRequiredException(Exception):
    """Exception raised when verification is required for login."""

    pass


class UnauthorizedException(Exception):
    pass


class LaunchAtMatcher:
    def __init__(self, cron_expr="30 20 * * 2", minute_tolerance=15):
        self.cron_expr = cron_expr
        self.minute_tolerance = minute_tolerance
        # Parse cron fields
        fields = cron_expr.strip().split()
        if len(fields) != 5:
            raise ValueError(f"Invalid cron expression: {cron_expr}")
        (
            self.cron_minute,
            self.cron_hour,
            self.cron_dom,
            self.cron_month,
            self.cron_wday,
        ) = fields

    @staticmethod
    def _parse_field(field, min_val, max_val):
        if field == "*":
            return set(range(min_val, max_val + 1))
        vals = set()
        for part in field.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                vals.update(range(start, end + 1))
            else:
                vals.add(int(part))
        return vals

    @staticmethod
    def _parse_cron_weekdays(field):
        # Cron: 0=Sunday, 1=Monday, ..., 6=Saturday
        # Python: 0=Monday, ..., 6=Sunday
        vals = set()
        if field == "*":
            return set(range(0, 7))
        for part in field.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                for cron_wd in range(start, end + 1):
                    py_wd = (cron_wd - 1) % 7
                    vals.add(py_wd)
            else:
                cron_wd = int(part)
                py_wd = (cron_wd - 1) % 7
                vals.add(py_wd)
        return vals

    def _nearest_cron_time(self, dt):
        # Only supports minute, hour, and weekday fields for simplicity
        minutes = self._parse_field(self.cron_minute, 0, 59)
        hours = self._parse_field(self.cron_hour, 0, 23)
        weekdays = self._parse_cron_weekdays(self.cron_wday)
        # Find the closest time in the past or future matching the cron
        # Search up to 1 week in both directions
        best_dt = None
        best_delta = None
        for offset in range(-7 * 24 * 60, 7 * 24 * 60 + 1):
            candidate = dt + datetime.timedelta(minutes=offset)
            if (
                candidate.minute in minutes
                and candidate.hour in hours
                and candidate.weekday() in weekdays
            ):
                delta = abs((candidate - dt).total_seconds()) / 60
                if best_delta is None or delta < best_delta:
                    best_delta = delta
                    best_dt = candidate
                    if best_delta == 0:
                        break
        return best_dt, best_delta

    def __call__(self, value):
        try:
            dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            dt_et = dt
            nearest, delta = self._nearest_cron_time(dt_et)
            if delta is not None and delta <= self.minute_tolerance:
                return (
                    True,
                    f"Launch time OK: {dt_et.strftime('%A %Y-%m-%d %H:%M %Z')} (nearest cron: {nearest.strftime('%A %Y-%m-%d %H:%M %Z') if nearest else nearest}, delta {delta:.1f} min)",
                )
            else:
                return (
                    False,
                    f"Time not within {self.minute_tolerance} min of cron ({self.cron_expr}): {dt_et.strftime('%A %Y-%m-%d %H:%M %Z')} (nearest: {nearest.strftime('%A %Y-%m-%d %H:%M %Z') if nearest else nearest}, delta {delta:.1f} min)",
                )
        except Exception as call_exception:
            return False, f"Invalid date format: {value} ({call_exception})"


class iRacingAPIHandler(requests.Session):
    def __init__(self, email, password, expectations_path=expectations_file):
        self.email = email
        self.password = password
        self.expectations = self._load_expectations(expectations_path)
        self.logged_in = False
        super().__init__()
        self.login()

    def login(self):
        url = "https://members-ng.iracing.com/auth"
        login_headers = {"Content-Type": "application/json"}
        data = {"email": self.email, "password": self.password}

        response = self.post(url, json=data, headers=login_headers)
        response_data = response.json()

        if response.status_code == 200 and response_data.get("authcode"):
            # # save the returned cookie
            # if response.cookies:
            #     self.cookies.update(response.cookies)
            self.logged_in = True
            return response_data
        elif (
            "verificationRequired" in response.json()
            and response.json()["verificationRequired"]
        ):
            raise VerificationRequiredException(
                f"Please log in to the iRacing member site. {response_data}"
            )
        else:
            raise RuntimeError("Error from iRacing: ", response_data)

    def _get_paged_data(self, url):
        if not self.logged_in:
            self.login()
            if not self.logged_in:
                raise UnauthorizedException("Not logged in to iRacing API")
        response = self.get(url)
        if response.status_code == 200:
            if "link" in response.json():
                data = self.get(response.json()["link"])
                return data.json() if data.status_code == 200 else {}
            else:
                return response.json()
        elif response.status_code == 401:
            self.logged_in = False
            return self._get_paged_data(url)
        else:
            response.raise_for_status()
            return {}

    def get_joinable_sessions_for_league(self, league_id):
        url = "https://members-ng.iracing.com/data/league/cust_league_sessions"
        r = self._get_paged_data(url)
        if "sessions" in r:
            return [
                s for s in r["sessions"]
                if (
                        s.get("league_id") == league_id
                        and (
                                datetime.datetime.strptime(s.get("launch_at"), "%Y-%m-%dT%H:%M:%SZ") >
                                datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
                        )
                )]
        else:
            return []

    def _compare_expectations(self, expected, actual, path=""):
        results = []
        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                results.append(
                    f"{FAIL_ICON} {path} type mismatch: expected dict, got {type(actual).__name__}"
                )
                return results
            for k, v in expected.items():
                new_path = f"{path}.{k}" if path else k
                if k in actual:
                    results.extend(self._compare_expectations(v, actual[k], new_path))
                else:
                    results.append(f"{UNKNOWN_ICON} {new_path} NOT FOUND")
        elif isinstance(expected, list):
            if not isinstance(actual, list):
                results.append(
                    f"{FAIL_ICON} {path} type mismatch: expected list, got {type(actual).__name__}"
                )
                return results
            for i, v in enumerate(expected):
                if i < len(actual):
                    results.extend(
                        self._compare_expectations(v, actual[i], f"{path}[{i}]")
                    )
                else:
                    results.append(
                        f"{UNKNOWN_ICON} {path}[{i}] NOT FOUND in actual list"
                    )
        elif callable(expected):
            ok, msg = expected(actual)  # pyright: ignore
            if ok:
                results.append(f"{PASS_ICON} {path} {msg}")
            else:
                results.append(f"{FAIL_ICON} {path} {msg}")
        else:
            if expected == actual:
                results.append(f"{PASS_ICON} {path} correct: {actual} == {expected}")
            else:
                results.append(f"{FAIL_ICON} {path} INCORRECT: {actual} != {expected}")
        return results

    @staticmethod
    def _count_mismatches(results):
        return sum(
            1
            for r in results
            if r.startswith(f"{FAIL_ICON}") or r.startswith(f"{UNKNOWN_ICON}")
        )

    def validate_session(self, session):
        # Support single or multiple expectations, each with a name
        expectations = self.expectations
        if not isinstance(expectations, list):
            expectations = [expectations]

        best_result = None
        best_mismatches = None
        best_expectation = None
        best_name = None
        all_expectation_results = {}

        for exp in expectations:
            # Support both legacy (dict) and named (dict with 'name' and 'expectation') formats
            if isinstance(exp, dict) and "expectation" in exp and "name" in exp:
                name = exp["name"]
                expectation = exp["expectation"]
            else:
                name = None
                expectation = exp

            results = self._compare_expectations(expectation, session)
            mismatches = self._count_mismatches(results)

            # Store results for all named expectations
            if name:
                all_expectation_results[name] = results

            # Track the best matching expectation
            if best_mismatches is None or mismatches < best_mismatches:
                best_mismatches = mismatches
                best_result = results
                best_expectation = expectation
                best_name = name

        key = f"{session.get('session_name', '<no name>')} -- {session.get('session_desc', '<no desc>')}"
        header = key

        # Return the best match and results from all expectations
        result = {
            header: best_result,
            "matched_expectation": best_expectation,
            "matched_expectation_name": best_name,
        }

        # Only include all_expectation_results if there are mismatches and multiple named expectations
        if best_mismatches and best_mismatches > 0 and len(all_expectation_results) > 0:
            result["all_expectation_results"] = all_expectation_results

        return result

    @staticmethod
    def _session_hash(session):
        """Compute a hash of the session's relevant fields for change detection."""
        s = copy.deepcopy(session)
        try:
            del s["weather"]["weather_url"]  # Remove weather_url as it changes frequently
        except KeyError:
            pass
        try:
            del s["weather"]["forecast_options"]["weather_seed"]
        except KeyError:
            pass
        for key in [
            "elig",
            "can_spot",
            "can_watch",
            "can_broadcast",
            "can_join",
            "num_drivers",
            "num_spotters",
            "num_spectators",
            "num_broadcasters",
            "available_reserved_broadcaster_slots",
            "num_spectator_slots",
            "available_spectator_slots",
            "entry_count",
            "team_entry_count",
            "populated",
            "broadcaster"
        ]:
            try:
                del s[key]  # Remove fields that change frequently
            except KeyError:
                pass
        # Sort the Admins array for consistency
        if "admins" in s and isinstance(s["admins"], list):
            s["admins"] = sorted(s["admins"], key=lambda x: x.get("cust_id", 0))
        return hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def _load_previous_summaries(path=state_file):
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    @staticmethod
    def _save_summaries(summaries, path=state_file):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(summaries, f, indent=2)

    @staticmethod
    def _load_expectations(path=expectations_file):
        with open(path, "r") as f:
            expectations = json.load(f)
        # Replace any 'launch_at' with a matcher callable
        for exp in expectations:
            if "expectation" in exp and isinstance(exp["expectation"], dict):
                launch_at = exp["expectation"].get("launch_at")
                if (
                    isinstance(launch_at, dict)
                    and "cron" in launch_at
                    and "margin" in launch_at
                ):
                    exp["expectation"]["launch_at"] = LaunchAtMatcher(
                        launch_at["cron"], launch_at["margin"]
                    )
                elif launch_at == "LaunchAtMatcher":
                    exp["expectation"]["launch_at"] = LaunchAtMatcher()
        return expectations

    @staticmethod
    def _compute_expectations_revision(path=expectations_file):
        """Compute a checksum of the expectations file for change detection."""
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def validate_sessions(self, league_id, summaries_path=state_file, force=False):
        sessions = self.get_joinable_sessions_for_league(league_id)
        if not sessions:
            return False

        prev_summaries = self._load_previous_summaries(summaries_path)
        new_summaries = {}
        results = []

        # Compute the current expectations revision
        current_revision = self._compute_expectations_revision()
        prev_revision = prev_summaries.get("revision")

        # If the revision has changed, force revalidation
        if current_revision != prev_revision:
            force = True

        for session in sessions:
            session_id = str(session.get("launch_at"))
            session_hash = self._session_hash(session)
            new_summaries[session_id] = session_hash
            if (
                session_id not in prev_summaries
                or prev_summaries[session_id] != session_hash
                or force
            ):
                print(
                    f"{session_hash} != {prev_summaries.get(session_id)} (FORCE={force})"
                )
                results.append(self.validate_session(session))

        # Save the new revision and summaries
        new_summaries["revision"] = current_revision
        self._save_summaries(new_summaries, summaries_path)

        return results

    @staticmethod
    def format_validation_results(results):
        formatted_results = []
        for result in results:
            # Extract session name and results
            session_name = list(result.keys())[0]
            session_results = result[session_name]

            # Check if there are any failing validations
            validation_failures = [
                sr
                for sr in session_results
                if sr.startswith(f"{FAIL_ICON}") or sr.startswith(f"{UNKNOWN_ICON}")
            ]

            # If no failures, show a success message
            if not validation_failures:
                result_string = f"# {session_name}:\n{PASS_ICON} All checks passed!"
                result_string += (
                    f"\n### Matched {result.get('matched_expectation_name', 'None')}"
                )
                formatted_results.append(result_string)
                continue

            # If we have failures and additional expectation results, show all of them
            result_string = f"# {session_name}:\n"

            # If there are additional expectations that were checked
            if (
                "all_expectation_results" in result
                and result["all_expectation_results"]
            ):
                all_exp_results = result["all_expectation_results"]

                # Add results for each expectation
                for exp_name, exp_results in all_exp_results.items():
                    exp_failures = [
                        er
                        for er in exp_results
                        if er.startswith(f"{FAIL_ICON}")
                        or er.startswith(f"{UNKNOWN_ICON}")
                    ]
                    if exp_failures:
                        result_string += f"\n### Failed Case: {exp_name}\n"
                        result_string += "\n".join(exp_failures)
                        result_string += "\n"
            else:
                # Fall back to just showing the failures from the best match
                result_string += "\n".join(validation_failures)

            formatted_results.append(result_string)

        output = "\n\n".join(formatted_results)
        return ">>> " + output


if __name__ == "__main__":
    runtime_email = os.environ.get("IRACING_API_EMAIL", "tyleragostino@gmail.com")
    runtime_password = os.environ.get("IRACING_API_PASSWORD")
    if not runtime_email or not runtime_password:
        print(
            "Please set IRACING_API_EMAIL and IRACING_API_PASSWORD environment variables."
        )
    else:
        handler = iRacingAPIHandler(runtime_email, runtime_password)
        last_auth_failed = False
        while True:
            try:
                beer_league = 8579
                league_sessions = handler.validate_sessions(beer_league)
                message_content = (
                    handler.format_validation_results(league_sessions)
                    if league_sessions
                    else False
                )
            except VerificationRequiredException as e:
                print(f"Verification required: {e}")
                if last_auth_failed:
                    message_content = False
                else:
                    message_content = "iRacing authentication expired. Please log in to the iRacing member site."
                    last_auth_failed = True
            except UnauthorizedException as e:
                print(f"Unauthorized, re-authenticating: {e}")
                try:
                    handler.login()
                except Exception as inner_e:
                    print(inner_e)
                    time.sleep(
                        60 * 60 * 24
                    )  # Wait a day before retrying after login failure
                finally:
                    message_content = False
            except Exception as e:
                print(f"Error during validation: {e}")
                message_content = False
            else:
                last_auth_failed = False
            try:
                if message_content:
                    headers = {"Content-Type": "application/json"}
                    print(message_content)
                    payload = {
                        "content": message_content[
                            :2000
                        ],  # Discord message limit is 2000 characters
                        "username": "Session Auditor",
                        "avatar_url": "https://cdn.discordapp.com/icons/981935710514839572/6d1658b24a272ad3e0efa97d9480fef5.png?size=320&quality=lossless",
                    }
                    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
                    wh_response = requests.post(
                        webhook_url, json=payload, headers=headers
                    )
                    if wh_response.status_code == 204:
                        print("Results sent to Discord successfully.")
                    else:
                        print(
                            f"Failed to send results to Discord: {wh_response.status_code} - {wh_response.text}"
                        )
            except Exception as e:
                print(f"Error sending to Discord: {e}")
            print(
                f"sleep until {(datetime.datetime.now() + datetime.timedelta(seconds=60 * 60)).strftime('%Y-%m-%d %H:%M:%S')}"
            )
            time.sleep(60 * 60)
