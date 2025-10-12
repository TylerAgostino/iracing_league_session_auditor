import json

StateItem = dict[str, str]


class StateManager:
    def __init__(self, state_file_path: str):
        self.state_file_path: str = state_file_path
        try:
            with open(self.state_file_path, "r") as f:
                _ = f.read()
        except FileNotFoundError:
            with open(self.state_file_path, "w") as f:
                _ = f.write("[]")
        with open(self.state_file_path, "r") as f:
            self.state_file_content: str = f.read()
            try:
                self.state: list[StateItem] = json.loads(self.state_file_content)
            except json.JSONDecodeError:
                self.state = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type: str, exc_value: str, traceback: str):
        with open(self.state_file_path, "w") as f:
            _ = f.write(json.dumps(self.state, indent=2))

    def item_changed(self, id: str, hash: str) -> bool:
        for existing_item in self.state:
            if existing_item["id"] == id:
                if existing_item["hash"] != hash:
                    existing_item["hash"] = hash
                    return True
                return False
        self.state.append({"id": id, "hash": hash})
        return True
