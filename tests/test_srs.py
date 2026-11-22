"""srs.py: nạp đúng dữ liệu của thầy và chặn host LLM ngoài allowlist (FR-07, NFR-02)."""

import pytest

from tracewise import srs


# bộ dữ liệu của thầy được nạp đủ và đúng, không thiếu file, không lệch số.
def test_alerts_whitelist_labels():
    alerts = srs.load_alerts()
    assert len(alerts) == 35 and alerts[0]["id"] == "LAB-0001"
    assert len(srs.load_whitelist()) == 24
    labels = srs.load_labels()
    assert set(labels) == {a["id"] for a in alerts}
    assert sum(lb["du_can_cu"] for lb in labels.values()) == 33
    assert labels["LAB-0031"]["ma_attack"] is None


# kich_ban chia đúng 17 nhóm độc lập, là nền cho bootstrap theo kịch bản mà bạn hỏi hôm trước.
def test_scenarios_give_17_independent_groups():
    labels = srs.load_labels()
    groups = {lb["kich_ban"] for lb in labels.values()}
    assert len(groups) == 17  # 15 kịch bản + INJ + khong_du
    assert labels["LAB-0001"]["kich_ban"] == labels["LAB-0002"]["kich_ban"] == "5710"
    assert {labels[i]["kich_ban"] for i in ("LAB-0033", "LAB-0034", "LAB-0035")} == {
        "INJ"
    }


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434",
        "http://127.0.0.1:11434/v1",
        "lab-llm:8000",
        "http://LOCALHOST:11434",
    ],
)
# các host hợp lệ phải được cho qua, kể cả khi viết theo nhiều kiểu khác nhau.
def test_allowed_hosts(url):
    assert srs.check_host(url).startswith("http")


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com",  # ghi chú trong allowlist_llm.yaml của thầy
        "http://localhost.evil.com",  # tên bắt đầu bằng localhost
        "http://localhost@evil.com",  # localhost là tên đăng nhập, host thật là evil.com
        "http://evil.com/localhost",  # localhost nằm trong đường dẫn
        "http://user:pass@localhost:11434",  # URL kèm thông tin đăng nhập
        "http://0.0.0.0:11434",
    ],
)
# các cách lách allowlist đều phải bị chặn, tức báo lỗi HostNotAllowed
def test_blocked_hosts(url):
    with pytest.raises(srs.HostNotAllowed):
        srs.check_host(url)
