from app.security import hash_password, verify_password, sha256_text
def test_password_roundtrip():
    encoded=hash_password("very-strong-password")
    assert verify_password("very-strong-password",encoded)
    assert not verify_password("wrong",encoded)
def test_sha():
    assert len(sha256_text("abc"))==64
