import csv, json
inc = json.load(open("output/training/incidents.json"))
truth = {r["event_id"]: int(r["is_malicious"]) for r in csv.DictReader(open("lab_data/training/ground_truth.csv"))}
print("threshold  TP FP FN  precision recall")
for t in (30, 40, 50, 65, 75, 85):
    pred = {e: 0 for e in truth}
    for i in inc:
        for e in i["event_ids"]:
            if e in pred and i["risk_score"] >= t:
                pred[e] = 1
    tp = sum(truth[e] and pred[e] for e in truth)
    fp = sum((not truth[e]) and pred[e] for e in truth)
    fn = sum(truth[e] and not pred[e] for e in truth)
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    print(f"{t:>9}  {tp:>2} {fp:>2} {fn:>2}  {p:>9.2f} {r:>6.2f}")
