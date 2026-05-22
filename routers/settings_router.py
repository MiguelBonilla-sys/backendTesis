"""Settings router — GET /settings returns current fusion parameters."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from auth.dependencies import require_auth
from core import constants

router = APIRouter()


class FusionSettings(BaseModel):
    alpha: float
    beta: float
    gamma: float
    theta: float
    lambda_: float
    ti_vt_weight: float
    ti_urlscan_weight: float
    ti_gsb_weight: float

    model_config = {"populate_by_name": True}

    def model_dump(self, **kwargs):
        d = super().model_dump(**kwargs)
        d["lambda"] = d.pop("lambda_")
        return d


@router.get(
    "/settings",
    response_model=None,
    summary="Get current fusion parameters",
)
async def get_settings(_: dict = Depends(require_auth)) -> dict:
    """Return the current fusion scoring parameters from constants."""
    return {
        "alpha": constants.ALPHA,
        "beta": constants.BETA,
        "gamma": constants.GAMMA,
        "theta": constants.THETA,
        "lambda": constants.LAMBDA,
        "ti_vt_weight": constants.W_VT,
        "ti_urlscan_weight": constants.W_URLSCAN,
        "ti_gsb_weight": constants.W_GSB,
    }
