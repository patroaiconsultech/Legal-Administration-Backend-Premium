from app.agent import retrieve
def test_trf4_retrieval():
    labels=[x["label"] for x in retrieve("O que falta do TRF4 para o eproc?")]
    assert "TRF4" in labels
