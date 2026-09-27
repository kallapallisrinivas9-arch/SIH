"""Optional ML adapter. The platform remains runnable without model packages or network access."""


def predict(text):
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        samples = ["team meeting notes and project update", "urgent verify password click link", "invoice payment attachment immediately", "welcome to the company orientation"]
        labels = [0, 1, 1, 0]
        vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        features = vectorizer.fit_transform(samples)
        model = LogisticRegression(max_iter=200).fit(features, labels)
        probability = float(model.predict_proba(vectorizer.transform([text]))[0][1])
        return {"score": round(probability * 100), "confidence": round(abs(probability - 0.5) * 200), "model": "tfidf-logistic-v1"}
    except (ImportError, ValueError):
        return {"score": 0, "confidence": 0, "model": "rules-only-fallback"}
