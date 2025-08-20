import base64
import hashlib
import requests
import datetime
import pytz
import json
import time
import os

PASS_ICON = "✅"
FAIL_ICON = "❌"
UNKNOWN_ICON = "🟡"

state_file = 'state/state.json'
expectations_file = 'expectations.json'

class VerificationRequiredException(Exception):
    """Exception raised when verification is required for login."""
    pass

class LaunchAtMatcher:
    def __init__(self, cron_expr="30 20 * * 2", minute_tolerance=15):
        self.cron_expr = cron_expr
        self.minute_tolerance = minute_tolerance
        # Parse cron fields
        fields = cron_expr.strip().split()
        if len(fields) != 5:
            raise ValueError(f"Invalid cron expression: {cron_expr}")
        self.cron_minute, self.cron_hour, self.cron_dom, self.cron_month, self.cron_wday = fields

    def _parse_field(self, field, minval, maxval):
        if field == '*':
            return set(range(minval, maxval+1))
        vals = set()
        for part in field.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                vals.update(range(start, end+1))
            else:
                vals.add(int(part))
        return vals

    def _parse_cron_weekdays(self, field):
        # Cron: 0=Sunday, 1=Monday, ..., 6=Saturday
        # Python: 0=Monday, ..., 6=Sunday
        vals = set()
        if field == '*':
            return set(range(0, 7))
        for part in field.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                for cron_wd in range(start, end+1):
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
        for offset in range(-7*24*60, 7*24*60+1):
            candidate = dt + datetime.timedelta(minutes=offset)
            if (candidate.minute in minutes and
                candidate.hour in hours and
                candidate.weekday() in weekdays):
                delta = abs((candidate - dt).total_seconds()) / 60
                if best_delta is None or delta < best_delta:
                    best_delta = delta
                    best_dt = candidate
                    if best_delta == 0:
                        break
        return best_dt, best_delta

    def __call__(self, value):
        try:
            dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
            dt_et = dt
            nearest, delta = self._nearest_cron_time(dt_et)
            if delta is not None and delta <= self.minute_tolerance:
                return True, f"Launch time OK: {dt_et.strftime('%A %Y-%m-%d %H:%M %Z')} (nearest cron: {nearest.strftime('%A %Y-%m-%d %H:%M %Z')}, delta {delta:.1f} min)"
            else:
                return False, f"Time not within {self.minute_tolerance} min of cron ({self.cron_expr}): {dt_et.strftime('%A %Y-%m-%d %H:%M %Z')} (nearest: {nearest.strftime('%A %Y-%m-%d %H:%M %Z')}, delta {delta:.1f} min)"
        except Exception as e:
            return False, f"Invalid date format: {value} ({e})"

class iRacingAPIHandler(requests.Session):
    def __init__(self, email, password, expectations_path=expectations_file):
        self.email = email
        self.password = password
        self.expectations = self._load_expectations(expectations_path)
        super().__init__()
        self.login()

    def login(self):
        url = 'https://members-ng.iracing.com/auth'
        headers = {'Content-Type': 'application/json'}
        data = {
            "email": self.email,
            "password": self.password
        }

        response = self.post(url, json=data, headers=headers)

        if response.status_code == 200:
            # save the returned cookie
            if response.cookies:
                self.cookies.update(response.cookies)
            if 'verificationRequired' in response.json() and response.json()['verificationRequired']:
                raise VerificationRequiredException("Please log in to the iRacing member site.")
            return response.json()
        else:
            response.raise_for_status()
            return None

    def _get_paged_data(self, url):
        response = self.get(url)
        if response.status_code == 200:
            if 'link' in response.json():
                data = self.get(response.json()['link'])
                return data.json() if data.status_code == 200 else None
            else:
                return response.json()
        else:
            response.raise_for_status()
            return None

    def get_joinable_sessions_for_league(self, league_id):
        url = f'https://members-ng.iracing.com/data/league/cust_league_sessions'
        r =  self._get_paged_data(url)
        if 'sessions' in r:
            return [s for s in r['sessions'] if s.get('league_id') == league_id]
        else:
            return []

    def _compare_expectations(self, expected, actual, path=""):
        results = []
        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                results.append(f"{FAIL_ICON} {path} type mismatch: expected dict, got {type(actual).__name__}")
                return results
            for k, v in expected.items():
                new_path = f"{path}.{k}" if path else k
                if k in actual:
                    results.extend(self._compare_expectations(v, actual[k], new_path))
                else:
                    results.append(f"{UNKNOWN_ICON} {new_path} NOT FOUND")
        elif isinstance(expected, list):
            if not isinstance(actual, list):
                results.append(f"{FAIL_ICON} {path} type mismatch: expected list, got {type(actual).__name__}")
                return results
            for i, v in enumerate(expected):
                if i < len(actual):
                    results.extend(self._compare_expectations(v, actual[i], f"{path}[{i}]") )
                else:
                    results.append(f"{UNKNOWN_ICON} {path}[{i}] NOT FOUND in actual list")
        elif callable(expected):
            ok, msg = expected(actual)
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
        return sum(1 for r in results if r.startswith(f"{FAIL_ICON}") or r.startswith(f"{UNKNOWN_ICON}"))

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
            if isinstance(exp, dict) and 'expectation' in exp and 'name' in exp:
                name = exp['name']
                expectation = exp['expectation']
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
            'matched_expectation': best_expectation,
            'matched_expectation_name': best_name
        }

        # Only include all_expectation_results if there are mismatches and multiple named expectations
        if best_mismatches > 0 and len(all_expectation_results) > 0:
            result['all_expectation_results'] = all_expectation_results

        return result

    def _session_hash(self, session):
        """Compute a hash of the session's relevant fields for change detection."""
        relevant = {
            'session_id': session.get('session_id'),
            'session_name': session.get('session_name'),
            'session_desc': session.get('session_desc'),
            # Add more fields if needed for change detection
        }
        return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()

    def _load_previous_summaries(self, path=state_file):
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        return {}

    def _save_summaries(self, summaries, path=state_file):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(summaries, f, indent=2)

    def _load_expectations(self, path=expectations_file):
        with open(path, 'r') as f:
            expectations = json.load(f)
        # Replace any 'launch_at' with a matcher callable
        for exp in expectations:
            if 'expectation' in exp and isinstance(exp['expectation'], dict):
                launch_at = exp['expectation'].get('launch_at')
                if isinstance(launch_at, dict) and 'cron' in launch_at and 'margin' in launch_at:
                    exp['expectation']['launch_at'] = LaunchAtMatcher(launch_at['cron'], launch_at['margin'])
                elif launch_at == 'LaunchAtMatcher':
                    exp['expectation']['launch_at'] = LaunchAtMatcher()
        return expectations

    def validate_sessions(self, league_id, summaries_path=state_file, force=False):
        sessions = self.get_joinable_sessions_for_league(league_id)
        if not sessions:
            return ["No joinable sessions found for the league."]

        prev_summaries = self._load_previous_summaries(summaries_path)
        new_summaries = {}
        results = []
        for session in sessions:
            session_id = str(session.get('launch_at'))
            session_hash = self._session_hash(session)
            new_summaries[session_id] = session_hash
            if session_id not in prev_summaries or prev_summaries[session_id] != session_hash or force:
                results.append(self.validate_session(session))
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
            validation_failures = [sr for sr in session_results if sr.startswith(f"{FAIL_ICON}") or sr.startswith(f"{UNKNOWN_ICON}")];

            # If no failures, show a success message
            if not validation_failures:
                result_string = f">>> # {session_name}:\n{PASS_ICON} All checks passed!"
                formatted_results.append(result_string)
                continue

            # If we have failures and additional expectation results, show all of them
            result_string = f">>> # {session_name}:\n"

            # Get matched expectation name
            matched_expectation_name = result.get('matched_expectation_name')

            # If there are additional expectations that were checked
            if 'all_expectation_results' in result and result['all_expectation_results']:
                all_exp_results = result['all_expectation_results']

                # Add results for each expectation
                for exp_name, exp_results in all_exp_results.items():
                    exp_failures = [er for er in exp_results if er.startswith(f"{FAIL_ICON}") or er.startswith(f"{UNKNOWN_ICON}")]
                    if exp_failures:
                        result_string += f"\n### Failed Case: {exp_name}\n"
                        result_string += "\n".join(exp_failures)
                        result_string += "\n"
            else:
                # Fall back to just showing the failures from the best match
                result_string += "\n".join(validation_failures)

            formatted_results.append(result_string)

        output = "\n\n".join(formatted_results)
        return output

if __name__ == "__main__":
    email = os.environ.get('IRACING_API_EMAIL', "tyleragostino@gmail.com")
    password = os.environ.get('IRACING_API_PASSWORD')
    if not email or not password:
        print("Please set IRACING_API_EMAIL and IRACING_API_PASSWORD environment variables.")
    else:
        last_auth_failed = False
        while True:
            try:
                handler = iRacingAPIHandler(email, password)
                league_id = 8579
                results = handler.validate_sessions(league_id)
                message_content = handler.format_validation_results(results) if results else False
                last_auth_failed = False
            except VerificationRequiredException as e:
                print(f"Verification required: {e}")
                if last_auth_failed:
                    message_content = False
                else:
                    message_content = "iRacing authentication expired. Please log in to the iRacing member site."
                    last_auth_failed = True
            if message_content:
                headers = {'Content-Type': 'application/json'}
                print(message_content)
                payload = {
                    "content": message_content[:2000],  # Discord message limit is 2000 characters
                    "username": "Session Auditor",
                    "avatar_url": "https://cdn.discordapp.com/icons/981935710514839572/6d1658b24a272ad3e0efa97d9480fef5.png?size=320&quality=lossless"
                }
                webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
                response = requests.post(webhook_url, json=payload, headers=headers)
                if response.status_code == 204:
                    print("Results sent to Discord successfully.")
                else:
                    print(f"Failed to send results to Discord: {response.status_code} - {response.text}")
            time.sleep(60 * 60 * 24)