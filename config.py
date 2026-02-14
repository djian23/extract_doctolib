from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    doctolib_email: str = ""
    doctolib_password: str = ""
    doctolib_base_url: str = "https://pro.doctolib.fr"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
