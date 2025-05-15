# core/config.py
from typing import Dict
import os
import json
from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API Configuration
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Protection System API"
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # MongoDB Configuration
    MONGODB_URL: str = Field(default="mongodb://localhost:27017", env="MONGODB_URL")
    MONGODB_DB_NAME: str = Field(default="protection_system", env="MONGODB_DB_NAME")
    
    # Redis Configuration
    REDIS_URL: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    REDIS_TTL: int = Field(default=3600, env="REDIS_TTL")  # 1 hour
    
    # ML Model Configuration
    MODEL_PATH: str = Field(default="models", env="MODEL_PATH")
    
    # Predictor Weights (must sum to 1.0)
    PREDICTOR_WEIGHTS: Dict[str, float] = Field(
        default={
            "access_time": 0.3,
            "auth_behavior": 0.4,
            "session_anomaly": 0.3
        }
    )
    
    # Anomaly detection Thresholds
    ACCESS_TIME_CONTAMINATION: float = Field(default=0.05, env="ACCESS_TIME_CONTAMINATION")
    AUTH_BEHAVIOR_THRESHOLD: float = Field(default=0.7, env="AUTH_BEHAVIOR_THRESHOLD")
    SESSION_ANOMALY_CONTAMINATION: float = Field(default=0.05, env="SESSION_ANOMALY_CONTAMINATION")
    
    # Risk Thresholds
    RISK_THRESHOLD_LOW: float = Field(default=0.3, env="RISK_THRESHOLD_LOW")
    RISK_THRESHOLD_HIGH: float = Field(default=0.7, env="RISK_THRESHOLD_HIGH")
    
    # API Response Time Requirements
    MAX_RESPONSE_TIME: float = Field(default=0.2, env="MAX_RESPONSE_TIME")  # 200ms
    
    # Feature Configuration
    ACCESS_TIME_WINDOW_HOURS: int = Field(default=24, env="ACCESS_TIME_WINDOW_HOURS")
    AUTH_BEHAVIOR_LOOKBACK_DAYS: int = Field(default=30, env="AUTH_BEHAVIOR_LOOKBACK_DAYS")
    SESSION_HISTORY_LIMIT: int = Field(default=100, env="SESSION_HISTORY_LIMIT")
    
    # Training Configuration
    TRAINING_DATA_SIZE: int = Field(default=10000, env="TRAINING_DATA_SIZE")
    ANOMALY_PERCENTAGE: float = Field(default=0.05, env="ANOMALY_PERCENTAGE")
    
    @validator('PREDICTOR_WEIGHTS', pre=True)
    def parse_weights(cls, v):
        """Parse JSON string to dict if needed"""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                raise ValueError("PREDICTOR_WEIGHTS must be valid JSON")
        return v
    
    @validator('PREDICTOR_WEIGHTS')
    def validate_weights(cls, v):
        """Validate that predictor weights sum to 1.0"""
        weight_sum = sum(v.values())
        if abs(weight_sum - 1.0) > 0.001:  # Allow small floating point errors
            raise ValueError(f"Predictor weights must sum to 1.0, got {weight_sum}")
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "allow"  # Allow extra fields that aren't defined


settings = Settings()