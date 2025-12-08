from symexec_engine.example import run_example


def test_example_finds_oob_bug():
    lines = run_example()
    assert any("OOB_LOAD" in line or "out-of-bounds" in line for line in lines)
    joined = "\n".join(lines)
    assert "idx" in joined
