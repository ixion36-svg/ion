import json

from ion.core.config import Config


def _load(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return Config.from_file(path), path


def test_saved_default_from_before_the_upgrade_reads_every_destination(tmp_path):
    cfg, _ = _load(tmp_path, {"tide_space": "default"})
    assert cfg.tide_space == ""


def test_default_chosen_after_the_upgrade_is_kept(tmp_path):
    cfg, path = _load(tmp_path, {"tide_space": "default"})
    cfg.tide_space = "default"
    cfg.to_file(path)
    assert Config.from_file(path).tide_space == "default"


def test_any_other_saved_space_is_left_alone(tmp_path):
    cfg, _ = _load(tmp_path, {"tide_space": "soc-staging"})
    assert cfg.tide_space == "soc-staging"
