import json

from django.forms import ModelForm
from pydantic import BaseModel, ConfigDict
from pydantic_settings import BaseSettings
from rest_framework import serializers


class ProfilePatch(BaseModel):
    # ruleid: traust-python-mass-assignment-extra-allow
    model_config = ConfigDict(extra="allow")
    nickname: str | None = None


class LegacyPatch(BaseModel):
    class Config:
        # ruleid: traust-python-mass-assignment-extra-allow
        extra = "allow"


class StrictPatch(BaseModel):
    # ok: traust-python-mass-assignment-extra-allow
    model_config = ConfigDict(extra="forbid")


class Runtime(BaseSettings):
    # ok: traust-python-mass-assignment-extra-allow
    model_config = ConfigDict(extra="allow")


class BadgeForm(ModelForm):
    class Meta:
        model = object
        # ruleid: traust-python-mass-assignment-model-all-fields
        fields = "__all__"


class BadgeSerializer(serializers.ModelSerializer):
    class Meta:
        model = object
        # ok: traust-python-mass-assignment-model-all-fields
        fields = ["id", "label"]


def enroll(request, Member):
    payload = json.loads(request.body)
    # ruleid: traust-python-mass-assignment-request-splat
    Member.objects.create(**payload)


def amend(request, member):
    for key, value in request.data.items():
        # ruleid: traust-python-mass-assignment-request-splat
        setattr(member, key, value)


def relabel(request, Member):
    # ok: traust-python-mass-assignment-request-splat
    Member.objects.filter(pk=1).update(label=request.data["label"])
