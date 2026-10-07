import string

import pytest

from seckit import hashing, password
from seckit.cli import main


def test_common_and_short_passwords_are_very_weak():
    assert password.assess("password")["score"] == 0
    assert password.assess("abc")["score"] == 0


def test_strong_password_scores_high():
    r = password.assess("v7#Qm2$zLp9!xRt4")
    assert r["score"] >= 3 and r["issues"] == []


def test_detects_sequences_and_repeats():
    assert password.has_sequence("xxabcdxx") and password.has_sequence("1234")
    assert password.has_repeats("aaab") and not password.has_repeats("abab")


def test_generator_contains_all_classes():
    for _ in range(50):
        pw = password.generate(12)
        assert len(pw) == 12
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(c not in string.ascii_letters + string.digits for c in pw)


def test_generator_rejects_short_length_and_is_random():
    with pytest.raises(ValueError):
        password.generate(4)
    assert password.generate(20) != password.generate(20)


def test_hash_and_verify():
    stored = hashing.hash_password("s3cret", iterations=1000)
    assert hashing.verify_password("s3cret", stored)
    assert not hashing.verify_password("wrong", stored)
    assert not hashing.verify_password("s3cret", "garbage")
    assert stored != hashing.hash_password("s3cret", iterations=1000)  # random salt


def test_file_checksum(tmp_path):
    f = tmp_path / "a.txt"; f.write_text("hello")
    assert hashing.file_checksum(str(f)) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_cli_verify_exit_codes(capsys):
    stored = hashing.hash_password("pw", iterations=1000)
    assert main(["verify", "pw", stored]) == 0
    assert main(["verify", "bad", stored]) == 1
