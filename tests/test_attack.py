"""attack.py: đọc đúng ATT&CK 18.1 và 24 mã của thầy khớp tên, tactic."""

from tracewise import srs
from tracewise.attack import load_attack, tactic_slug


def test_version_and_count():
    table, version = load_attack()
    assert version == "18.1"
    assert len(table) == 691  # kỹ thuật + kỹ thuật con còn hiệu lực


def test_teacher_whitelist_matches_18_1():
    table, _ = load_attack()
    for row in srs.load_whitelist():
        t = table[row["ma"]]
        assert t.name == row["ten"], row["ma"]
        assert set(t.tactics) == {tactic_slug(x) for x in row["chien_thuat"]}, row["ma"]


def test_one_technique_many_tactics():
    table, _ = load_attack()
    assert set(table["T1053.005"].tactics) == {
        "execution",
        "persistence",
        "privilege-escalation",
    }


def test_platforms_and_data_components():
    table, _ = load_attack()
    assert "Windows" in table["T1003.001"].platforms
    assert "Linux" in table["T1548.003"].platforms
    assert "Process Creation" in table["T1059.001"].data_components
    assert "(Citation:" not in table["T1059.001"].description


def test_codes_from_newer_versions_are_absent():
    table, _ = load_attack()
    assert "T1685" not in table  # mã mới của v19, không có trong 18.1


def test_loaded_once():
    assert load_attack()[0] is load_attack()[0]  # lần gọi sau dùng lại kết quả (cache)
