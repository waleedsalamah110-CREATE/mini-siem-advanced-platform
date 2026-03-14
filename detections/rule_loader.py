import os
import yaml


def load_rules(rules_dir="rules"):
    rules = []

    if not os.path.exists(rules_dir):
        return rules

    for filename in os.listdir(rules_dir):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            path = os.path.join(rules_dir, filename)
            with open(path, "r", encoding="utf-8") as f:
                rules.append(yaml.safe_load(f))

    return rules
    
