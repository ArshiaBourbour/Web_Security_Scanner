class ScoreEngine:
    def __init__(self, analysis):
        self.analysis = analysis

    def calculate(self):

        score = 100

        weights = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}

        for f in self.analysis["findings"]:
            score -= weights.get(f["severity"], 0)

        score = max(0, score)

        return {
            "score": score,
            "risk": self.analysis["risk"],
            "grade": self.grade(score),
            "high": self.count("HIGH"),
            "medium": self.count("MEDIUM"),
            "low": self.count("LOW"),
        }

    def count(self, level):

        return sum(1 for f in self.analysis["findings"] if f["severity"] == level)

    def grade(self, score):

        if score >= 90:
            return "A+"
        if score >= 80:
            return "A"
        if score >= 70:
            return "B"
        if score >= 60:
            return "C"
        return "F"
