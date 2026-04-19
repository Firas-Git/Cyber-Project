import pandas as pd
from typing import Optional

_dataset: Optional[pd.DataFrame] = None


def set_dataset(df: pd.DataFrame) -> None:
    global _dataset
    _dataset = df


def get_dataset() -> Optional[pd.DataFrame]:
    return _dataset
