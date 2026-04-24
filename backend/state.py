import pandas as pd
from typing import Optional

_dataset: Optional[pd.DataFrame] = None
_active_model: str = "random_forest"


def set_dataset(df: pd.DataFrame) -> None:
    global _dataset
    _dataset = df


def get_dataset() -> Optional[pd.DataFrame]:
    return _dataset


def set_active_model(model_key: str) -> None:
    global _active_model
    _active_model = model_key


def get_active_model() -> str:
    return _active_model
