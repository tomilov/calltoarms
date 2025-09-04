import argparse
import contextlib
import logging
from abc import ABC, abstractmethod
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from filelock import FileLock
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from .util import get_base_path

logger = logging.getLogger(__name__)


class Account(BaseModel):
    model_config = ConfigDict(extra="ignore")

    alias: str | None = None
    login: str | None = None
    password: str | None = None
    network: str | None = None
    fast_relogin: bool | None = None
    comment: str | None = None
    color: str | None = None


class Settings(BaseSettings, ABC):
    model_config = SettingsConfigDict(extra="ignore")

    windowleft: float | None = None
    windowtop: float | None = None
    windowwidth: float | None = None
    windowheight: float | None = None

    exe_path: Path | None = None
    accounts: list[Account] = Field(default_factory=list)

    def find_account(self, alias: str, /) -> Account | None:
        for account in self.accounts:
            if account.alias == alias:
                return account
        return None

    def remove_account(self, alias: str, /) -> Account | None:
        for i, account in enumerate(self.accounts):
            if account.alias == alias:
                return self.accounts.pop(i)
        return None

    @abstractmethod
    def save(self) -> None:
        pass

    @classmethod
    @contextlib.contextmanager
    def get_settings(cls, yaml_path: Path, *, timeout: float) -> Generator["Settings"]:
        class YamlSettings(Settings):
            if TYPE_CHECKING:
                assert isinstance(cls.model_config, dict)
            model_config = cls.model_config.copy()
            model_config.update({"yaml_file": yaml_path})

            @classmethod
            def settings_customise_sources(
                cls,
                settings_cls: type[BaseSettings],
                init_settings: PydanticBaseSettingsSource,  # noqa: ARG003
                env_settings: PydanticBaseSettingsSource,
                dotenv_settings: PydanticBaseSettingsSource,  # noqa: ARG003
                file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003
            ) -> tuple[PydanticBaseSettingsSource, ...]:
                return (
                    YamlConfigSettingsSource(settings_cls, yaml_path),
                    env_settings,
                )

            def save(self) -> None:
                data = self.model_dump(
                    mode="json", exclude_defaults=True, exclude_none=True
                )
                with yaml_path.open("w", encoding="utf-8") as f:
                    yaml.safe_dump(data, f)
                logger.info("%s", "Settings saved")

        lock_file = yaml_path.with_name(f"{yaml_path.name}.lock")
        with FileLock(lock_file, timeout=timeout):
            settings = YamlSettings()
            try:
                yield settings
            finally:
                settings.save()


def setup_parser_settings(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=(get_base_path() / "settings.yaml"),
        help="Path of file with settings and accounts in YAML format.",
    )
