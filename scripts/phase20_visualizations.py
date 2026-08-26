import csv
from collections import Counter, defaultdict

import matplotlib.pyplot as plt


CSV_PATH = "results/final_analysis.csv"


def load_data():
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


rows = load_data()

# ---------------------------------------------------------
# Figure 1 — Overall reachability
# ---------------------------------------------------------

reachability = Counter(row["reachability"] for row in rows)

labels = [
    "Reachable",
    "Not reachable",
    "Conditionally reachable",
    "Unclear",
]

values = [
    reachability.get("reachable", 0),
    reachability.get("not_reachable", 0),
    reachability.get("conditionally_reachable", 0),
    reachability.get("unknown", 0),
]

plt.figure(figsize=(8, 5))
bars = plt.bar(labels, values)

plt.title("Reachability of Manually Assessed Findings")
plt.ylabel("Number of findings")
plt.ylim(0, max(values) + 3)

for bar, value in zip(bars, values):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.15,
        f"{value} ({value / len(rows):.0%})",
        ha="center",
    )

plt.tight_layout()
plt.savefig(
    "results/phase20_reachability.png",
    dpi=300,
    bbox_inches="tight",
)
plt.close()


# ---------------------------------------------------------
# Figure 2 — Dependency type vs reachability
# ---------------------------------------------------------

dependency_types = [
    "direct",
    "transitive",
    "direct-dev-test",
]

display_names = {
    "direct": "Direct",
    "transitive": "Transitive",
    "direct-dev-test": "Direct dev/test",
}

reachability_types = [
    "not_reachable",
    "conditionally_reachable",
    "reachable",
]

counts = defaultdict(Counter)

for row in rows:
    counts[row["dependency_type"]][row["reachability"]] += 1


x = range(len(dependency_types))
bottom = [0] * len(dependency_types)

plt.figure(figsize=(8, 5))

for reachability_type in reachability_types:
    values = [
        counts[dependency_type][reachability_type]
        for dependency_type in dependency_types
    ]

    bars = plt.bar(
        x,
        values,
        bottom=bottom,
        label=reachability_type.replace("_", " ").title(),
    )

    bottom = [
        bottom[i] + values[i]
        for i in range(len(values))
    ]

plt.xticks(
    list(x),
    [display_names[x] for x in dependency_types],
)

plt.ylabel("Number of findings")
plt.title("Reachability by Dependency Type")
plt.legend()

plt.tight_layout()
plt.savefig(
    "results/phase20_dependency_reachability.png",
    dpi=300,
    bbox_inches="tight",
)
plt.close()

print("Created:")
print("  results/phase20_reachability.png")
print("  results/phase20_dependency_reachability.png")
